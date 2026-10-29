//! Logs that rotate into numbered segments behind signed checkpoints, written before the
//! implementation.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use mohar_core::store::{
    FileLog, OpenError, SegmentBreak, SignatureChecks, for_each_log_receipt, read_checkpoints,
    segments, verify_dir,
};
use mohar_core::{Action, BreakKind, Decision, Entry, VerifyingKey, parse_public_key};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-seg-{name}-{}", std::process::id()));
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

/// One receipt line is a little over 400 bytes, so this rotates about every three receipts.
const SMALL: u64 = 1200;

/// A log of `n` receipts that rotated at [`SMALL`] bytes.
fn rotated(name: &str, n: u64) -> PathBuf {
    let dir = temp_dir(name);
    let mut log = FileLog::init(&dir).expect("init");
    log.set_segment_bytes(Some(SMALL));
    for i in 0..n {
        log.append(entry(i)).expect("append");
    }
    dir
}

fn key(dir: &Path) -> VerifyingKey {
    parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("public key"))
        .expect("parses")
}

fn verify(dir: &Path, from: Option<u64>) -> Result<mohar_core::store::Stats, OpenError> {
    verify_dir(dir, &[], &key(dir), SignatureChecks::Every, from)
}

#[test]
fn a_log_rotates_into_numbered_segments_each_closed_by_a_checkpoint() {
    let dir = rotated("rotate", 20);
    let segs = segments(&dir).expect("segments");
    assert!(segs.len() >= 4, "{} segments", segs.len());
    assert_eq!(segs[0].start, 0);
    assert!(segs.windows(2).all(|w| w[0].start < w[1].start));
    let counts: Vec<u64> = read_checkpoints(&dir.join("checkpoints.jsonl"))
        .expect("checkpoints")
        .iter()
        .map(|c| c.count)
        .collect();
    for w in segs.windows(2) {
        assert!(
            counts.contains(&w[1].start),
            "segment ending at {}",
            w[1].start
        );
    }
    // The active file stays below the limit plus one receipt.
    assert!(
        fs::metadata(dir.join("receipts.jsonl"))
            .expect("active")
            .len()
            < SMALL + 600
    );

    let stats = verify(&dir, None).expect("verifies across segments");
    assert_eq!((stats.first, stats.receipts), (0, 20));

    let mut seqs = Vec::new();
    for_each_log_receipt(&dir, |r| seqs.push(r.seq)).expect("reads every segment");
    assert_eq!(seqs, (0..20).collect::<Vec<_>>());
}

#[test]
fn a_rotated_log_reopens_and_keeps_appending_in_order() {
    let dir = rotated("reopen", 10);
    let mut log = FileLog::open(&dir).expect("reopens");
    assert_eq!(log.len(), 10);
    log.set_segment_bytes(Some(SMALL));
    for i in 10..16 {
        assert_eq!(log.append(entry(i)).expect("append").seq, i);
    }
    drop(log);
    assert_eq!(verify(&dir, None).expect("verifies").receipts, 16);
}

#[test]
fn without_a_size_the_log_never_rotates() {
    let dir = temp_dir("norotate");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..20 {
        log.append(entry(i)).expect("append");
    }
    assert!(segments(&dir).expect("segments").is_empty());
}

#[test]
fn archived_segments_can_be_removed_and_the_rest_still_verifies() {
    let dir = rotated("archive", 20);
    let segs = segments(&dir).expect("segments");
    fs::remove_file(&segs[0].path).expect("archive first");
    fs::remove_file(&segs[1].path).expect("archive second");
    let stats = verify(&dir, None).expect("the rest verifies");
    assert_eq!((stats.first, stats.receipts), (segs[2].start, 20));

    // The daemon's own open works too, and appends carry on.
    let mut log = FileLog::open(&dir).expect("opens");
    assert_eq!(log.append(entry(20)).expect("append").seq, 20);
}

#[test]
fn a_segment_missing_from_the_middle_is_a_gap() {
    let dir = rotated("gap", 20);
    let segs = segments(&dir).expect("segments");
    fs::remove_file(&segs[1].path).expect("remove middle");
    match verify(&dir, None) {
        Err(OpenError::Segment(SegmentBreak::Gap {
            expected, found, ..
        })) => assert_eq!((expected, found), (segs[1].start, segs[2].start)),
        other => panic!("{other:?}"),
    }
    assert!(FileLog::open(&dir).is_err());
}

#[test]
fn a_segment_cut_short_is_refused() {
    let dir = rotated("short", 20);
    let segs = segments(&dir).expect("segments");
    let text = fs::read_to_string(&segs[1].path).expect("read");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.pop();
    fs::write(&segs[1].path, lines.join("\n") + "\n").expect("write");
    assert!(matches!(
        verify(&dir, None),
        Err(OpenError::Segment(SegmentBreak::Gap { .. }))
    ));
}

#[test]
fn a_closed_segment_without_its_checkpoint_is_refused() {
    let dir = rotated("unclosed", 20);
    let segs = segments(&dir).expect("segments");
    let closing = segs[2].start;
    let path = dir.join("checkpoints.jsonl");
    let kept: Vec<String> = fs::read_to_string(&path)
        .expect("read")
        .lines()
        .filter(|l| !l.contains(&format!("\"count\":{closing},")))
        .map(String::from)
        .collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");
    match verify(&dir, None) {
        Err(OpenError::Segment(SegmentBreak::Unclosed { count, .. })) => assert_eq!(count, closing),
        other => panic!("{other:?}"),
    }
}

#[test]
fn archiving_without_the_checkpoint_at_the_new_start_is_refused() {
    let dir = rotated("noanchor", 20);
    let segs = segments(&dir).expect("segments");
    fs::remove_file(&segs[0].path).expect("archive");
    let start = segs[1].start;
    let path = dir.join("checkpoints.jsonl");
    let kept: Vec<String> = fs::read_to_string(&path)
        .expect("read")
        .lines()
        .filter(|l| !l.contains(&format!("\"count\":{start},")))
        .map(String::from)
        .collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");
    match verify(&dir, None) {
        Err(OpenError::Segment(SegmentBreak::NoAnchor { count })) => assert_eq!(count, start),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_changed_receipt_in_an_old_segment_is_named_by_its_position_in_the_log() {
    let dir = rotated("tamper", 20);
    let segs = segments(&dir).expect("segments");
    let text = fs::read_to_string(&segs[1].path).expect("read");
    fs::write(&segs[1].path, text.replacen("docs/", "src/", 1)).expect("write");
    match verify(&dir, None) {
        Err(OpenError::Chain(b)) => {
            assert_eq!(b.index as u64, segs[1].start);
            assert_eq!(b.kind, BreakKind::BadSignature);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn verification_can_start_at_any_checkpoint() {
    let dir = temp_dir("from");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..9 {
        log.append(entry(i)).expect("append");
        if i == 4 {
            log.checkpoint("2026-11-03T14:22:08.000Z")
                .expect("checkpoint");
        }
    }
    drop(log);
    let stats = verify(&dir, Some(5)).expect("from the checkpoint at 5");
    assert_eq!((stats.first, stats.receipts), (5, 9));
    // A receipt before the starting point no longer matters.
    let text = fs::read_to_string(dir.join("receipts.jsonl")).expect("read");
    fs::write(
        dir.join("receipts.jsonl"),
        text.replacen("docs/0.md", "docs/x.md", 1),
    )
    .expect("write");
    assert!(verify(&dir, Some(5)).is_ok());
    assert!(verify(&dir, None).is_err());
    // There is nothing signed at 4 to start from.
    assert!(matches!(
        verify(&dir, Some(4)),
        Err(OpenError::Segment(SegmentBreak::NoAnchor { count: 4 }))
    ));
}

#[test]
fn verification_from_a_checkpoint_in_a_rotated_log_skips_older_segments() {
    let dir = rotated("fromseg", 20);
    let segs = segments(&dir).expect("segments");
    // Anything in a segment wholly before the start isn't read.
    fs::write(&segs[0].path, "not a receipt\n").expect("write");
    let stats = verify(&dir, Some(segs[2].start)).expect("verifies from there");
    assert_eq!((stats.first, stats.receipts), (segs[2].start, 20));
}

#[test]
fn an_old_receipt_copied_after_the_start_is_not_skipped() {
    let dir = temp_dir("replay");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..6 {
        log.append(entry(i)).expect("append");
        if i == 2 {
            log.checkpoint("2026-11-03T14:22:08.000Z")
                .expect("checkpoint");
        }
    }
    drop(log);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let first = text.lines().next().expect("line").to_string();
    fs::write(&path, format!("{text}{first}\n")).expect("write");
    match verify(&dir, Some(3)) {
        Err(OpenError::Chain(b)) => {
            assert_eq!(b.index, 6);
            assert_eq!(b.kind, BreakKind::WrongSequence);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_empty_active_file_removed_by_a_crash_is_recreated() {
    let dir = temp_dir("recreate");
    let mut log = FileLog::init(&dir).expect("init");
    log.set_segment_bytes(Some(1));
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    // Every append rotated, so the active file is empty; a crash before it was created leaves none.
    assert_eq!(
        fs::metadata(dir.join("receipts.jsonl"))
            .expect("active")
            .len(),
        0
    );
    fs::remove_file(dir.join("receipts.jsonl")).expect("remove");
    assert_eq!(verify(&dir, None).expect("verifies").receipts, 3);
    let mut log = FileLog::open(&dir).expect("opens and recreates it");
    assert_eq!(log.append(entry(3)).expect("append").seq, 3);
}

#[test]
fn init_refuses_a_directory_with_segments() {
    let dir = rotated("noclobber", 6);
    fs::remove_file(dir.join("receipts.jsonl")).expect("remove");
    fs::remove_file(dir.join("key.ed25519")).expect("remove");
    assert!(matches!(
        FileLog::init(&dir),
        Err(OpenError::AlreadyExists(_))
    ));
}

#[test]
fn a_stray_file_in_segments_is_refused() {
    let dir = rotated("stray", 6);
    fs::write(dir.join("segments").join("notes.txt"), "x").expect("write");
    assert!(matches!(
        segments(&dir),
        Err(OpenError::Segment(SegmentBreak::BadName { .. }))
    ));
    assert!(verify(&dir, None).is_err());
}

#[test]
fn an_unreadable_line_in_a_segment_names_the_file() {
    let dir = rotated("badline", 20);
    let segs = segments(&dir).expect("segments");
    let text = fs::read_to_string(&segs[1].path).expect("read");
    fs::write(&segs[1].path, format!("{text}{{\"v\":\n")).expect("write");
    match verify(&dir, None) {
        Err(OpenError::UnreadableSegment { path, .. }) => assert_eq!(path, segs[1].path),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_strict_log_without_its_privacy_key_is_refused_after_rotation() {
    let dir = temp_dir("strict");
    let mut log = FileLog::init_strict(&dir).expect("init");
    log.set_segment_bytes(Some(1));
    for i in 0..3 {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    fs::remove_file(dir.join("privacy.key")).expect("remove key");
    fs::remove_file(dir.join("identities.jsonl")).expect("erase");
    assert!(matches!(
        FileLog::open(&dir),
        Err(OpenError::PrivacyKeyMissing(_))
    ));
}

#[test]
fn with_every_segment_archived_the_active_file_starts_at_its_first_receipt() {
    let dir = rotated("allgone", 20);
    let segs = segments(&dir).expect("segments");
    for s in &segs {
        fs::remove_file(&s.path).expect("archive");
    }
    // The active file starts after the last segment, whose receipts are gone with it.
    let in_active = mohar_core::store::read_receipts(&dir.join("receipts.jsonl"))
        .expect("read")
        .len() as u64;
    let active_start = 20 - in_active;
    assert!(active_start > 0);
    let stats = verify(&dir, None).expect("verifies from the checkpoint at its start");
    assert_eq!((stats.first, stats.receipts), (active_start, 20));
    let mut log = FileLog::open(&dir).expect("opens");
    assert_eq!(log.append(entry(20)).expect("append").seq, 20);
}

#[test]
fn with_every_segment_archived_and_no_active_receipts_numbering_carries_on() {
    let dir = temp_dir("allgone-empty");
    let mut log = FileLog::init(&dir).expect("init");
    log.set_segment_bytes(Some(1));
    for i in 0..4 {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    for s in segments(&dir).expect("segments") {
        fs::remove_file(&s.path).expect("archive");
    }
    let stats = verify(&dir, None).expect("verifies");
    assert_eq!((stats.first, stats.receipts), (4, 4));
    let mut log = FileLog::open(&dir).expect("opens");
    assert_eq!(
        log.append(entry(4)).expect("append").seq,
        4,
        "never back to 0"
    );
    drop(log);
    assert_eq!(verify(&dir, None).expect("verifies").receipts, 5);
}

#[test]
fn a_log_that_never_rotated_still_must_start_at_receipt_zero() {
    let dir = temp_dir("nohead");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..6 {
        log.append(entry(i)).expect("append");
        if i == 2 {
            log.checkpoint("2026-11-03T14:22:08.000Z")
                .expect("checkpoint");
        }
    }
    drop(log);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let rest: Vec<&str> = text.lines().skip(3).collect();
    fs::write(&path, rest.join("\n") + "\n").expect("write");
    assert!(
        verify(&dir, None).is_err(),
        "cutting the head off isn't archiving"
    );
}
