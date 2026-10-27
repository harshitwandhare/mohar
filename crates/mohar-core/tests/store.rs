//! Behaviour of the on-disk log, written before the implementation.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use mohar_core::store::{FileLog, OpenError, for_each_receipt, read_receipts};
use mohar_core::{Action, BreakKind, Decision, Entry};

/// A fresh, empty directory under the system temp dir, unique to this test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn entry(i: u64) -> Entry {
    Entry {
        ts: "2026-11-03T14:22:07.000Z".into(),
        agent_id: "agent:test/7c1e".into(),
        action: Action {
            capability: "fs.edit.docs".into(),
            tool: "Edit".into(),
            target: format!("docs/{i}.md"),
            args_sha256: "c41b77d0".into(),
        },
        decision: Decision {
            result: "allow".into(),
            level: 1,
            by: "score".into(),
            review: false,
        },
        verification: None,
    }
}

#[test]
fn a_log_survives_being_closed_and_reopened() {
    let dir = temp_dir("reopen");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    drop(log);

    let mut log = FileLog::open(&dir).expect("reopen verifies");
    assert_eq!(log.len(), 3);
    let r = log.append(entry(3)).expect("append after reopen");
    assert_eq!(r.seq, 3);
    drop(log);
    assert_eq!(FileLog::open(&dir).expect("reopen again").len(), 4);
}

#[test]
fn init_refuses_to_overwrite_an_existing_log() {
    let dir = temp_dir("noclobber");
    FileLog::init(&dir).expect("first init");
    assert!(
        FileLog::init(&dir).is_err(),
        "second init must not replace the key or the log"
    );
}

#[test]
fn a_receipt_edited_on_disk_is_refused_on_open() {
    let dir = temp_dir("tamper");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..4 {
        log.append(entry(i)).expect("append");
    }
    drop(log);

    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    fs::write(
        &path,
        text.replacen("\"result\":\"allow\"", "\"result\":\"deny\"", 1),
    )
    .expect("write");

    match FileLog::open(&dir) {
        Err(OpenError::Chain(b)) => assert_eq!((b.index, b.kind), (0, BreakKind::BadSignature)),
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("tampered log must not open"),
    }
}

#[test]
fn a_last_line_cut_short_by_a_crash_is_reported() {
    let dir = temp_dir("truncated");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    drop(log);

    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    fs::write(&path, &text[..text.len() - 20]).expect("write");

    match FileLog::open(&dir) {
        Err(OpenError::Unreadable { line }) => assert_eq!(line, 3),
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("a torn write must not open silently"),
    }
}

#[cfg(unix)]
#[test]
fn the_signing_key_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("perms");
    FileLog::init(&dir).expect("init");
    let mode = fs::metadata(dir.join("key.ed25519"))
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_second_writer_is_refused_while_the_first_is_open() {
    let dir = temp_dir("lock");
    let first = FileLog::init(&dir).expect("init");
    match FileLog::open(&dir) {
        Err(OpenError::Locked(_)) => {}
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("two writers on one log must not both open"),
    }
    // Reading and verifying never needs the lock.
    assert!(mohar_core::store::read_receipts(&dir.join("receipts.jsonl")).is_ok());
    drop(first);
    FileLog::open(&dir).expect("the lock is released when the writer is dropped");
}

#[test]
fn an_empty_log_says_so_and_stops_saying_so_after_an_append() {
    let dir = temp_dir("empty");
    let mut log = FileLog::init(&dir).expect("init");
    assert!(log.is_empty());
    log.append(entry(0)).expect("append");
    assert!(!log.is_empty());
}

#[test]
fn blank_lines_between_receipts_and_checkpoints_are_skipped() {
    let dir = temp_dir("blank");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    log.checkpoint("2026-10-14T15:00:00.000Z")
        .expect("checkpoint");
    drop(log);
    for name in ["receipts.jsonl", "checkpoints.jsonl"] {
        let path = dir.join(name);
        let text = fs::read_to_string(&path).expect("read");
        fs::write(&path, text.replace('\n', "\n\n")).expect("write");
    }
    let log = FileLog::open(&dir).expect("blank lines are not receipts");
    assert_eq!(log.len(), 3);
}

#[test]
fn reading_stops_at_an_unreadable_line_after_handing_over_the_ones_before() {
    let dir = temp_dir("walk");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.insert(2, "{not a receipt");
    fs::write(&path, lines.join("\n") + "\n").expect("write");

    let mut seen = Vec::new();
    let err = for_each_receipt(&path, |r| seen.push(r.seq)).expect_err("must stop");
    assert!(matches!(err, OpenError::Unreadable { line: 3 }), "{err}");
    assert_eq!(seen, vec![0, 1]);
    assert!(matches!(
        read_receipts(&path),
        Err(OpenError::Unreadable { line: 3 })
    ));
}

#[test]
fn an_unreadable_checkpoint_line_names_its_file_and_line() {
    let dir = temp_dir("bad-checkpoint");
    let mut log = FileLog::init(&dir).expect("init");
    log.append(entry(0)).expect("append");
    log.checkpoint("2026-10-14T15:00:00.000Z")
        .expect("checkpoint");
    drop(log);
    let path = dir.join("checkpoints.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    fs::write(&path, text + "{\"v\":1\n").expect("write");
    match FileLog::open(&dir) {
        Err(OpenError::UnreadableCheckpoint { path: p, line: 2 }) => assert_eq!(p, path),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("opened a log with an unreadable checkpoint"),
    }
}
