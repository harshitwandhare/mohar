//! Checkpoints make a cut-off log detectable. Written before the implementation.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use mohar_core::checkpoint::{CheckpointBreak, verify_checkpoints};
use mohar_core::store::{FileLog, read_checkpoints, read_receipts};
use mohar_core::{Action, Decision, Entry, SigningKey, parse_public_key};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-ckpt-{name}-{}", std::process::id()));
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
        },
        verification: None,
    }
}

/// A log of `n` receipts with a checkpoint after receipt index `at`, and another at the end.
fn log_with_checkpoints(name: &str, n: u64, at: u64) -> PathBuf {
    let dir = temp_dir(name);
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..n {
        log.append(entry(i)).expect("append");
        if i == at {
            log.checkpoint("2026-11-03T15:00:00.000Z")
                .expect("checkpoint");
        }
    }
    log.checkpoint("2026-11-03T16:00:00.000Z")
        .expect("checkpoint");
    dir
}

fn check(dir: &Path) -> Result<(), CheckpointBreak> {
    let key =
        parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key")).expect("parse");
    let receipts = read_receipts(&dir.join("receipts.jsonl")).expect("receipts");
    let checkpoints = read_checkpoints(&dir.join("checkpoints.jsonl")).expect("checkpoints");
    verify_checkpoints(&checkpoints, &receipts, &key)
}

#[test]
fn checkpoints_on_an_intact_log_verify() {
    let dir = log_with_checkpoints("ok", 6, 2);
    assert_eq!(
        read_checkpoints(&dir.join("checkpoints.jsonl"))
            .expect("read")
            .len(),
        2
    );
    assert_eq!(check(&dir), Ok(()));
}

#[test]
fn removing_receipts_from_the_end_is_caught() {
    let dir = log_with_checkpoints("truncated", 6, 2);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = text.lines().take(4).collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");

    // The four remaining receipts still form a valid chain on their own.
    let key =
        parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key")).expect("parse");
    let receipts = read_receipts(&path).expect("receipts");
    assert_eq!(mohar_core::verify(&receipts, &key), Ok(()));

    // But the last checkpoint vouched for six.
    assert_eq!(
        check(&dir),
        Err(CheckpointBreak::LogTooShort {
            checkpoint: 1,
            expected: 6,
            found: 4
        })
    );
}

#[test]
fn a_rewritten_tail_with_a_fresh_key_is_caught() {
    let dir = log_with_checkpoints("rewritten", 4, 1);
    // An attacker with the receipts but not the key re-signs a different receipt 3 with a new key;
    // the chain check fails on its signature, and the checkpoint no longer matches either.
    let path = dir.join("receipts.jsonl");
    let mut receipts = read_receipts(&path).expect("receipts");
    receipts[3].action.target = "secrets.env".into();
    let key =
        parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key")).expect("parse");
    let checkpoints = read_checkpoints(&dir.join("checkpoints.jsonl")).expect("checkpoints");
    assert_eq!(
        verify_checkpoints(&checkpoints, &receipts, &key),
        Err(CheckpointBreak::HeadMismatch {
            checkpoint: 1,
            seq: 3
        })
    );
}

#[test]
fn a_checkpoint_signed_by_another_key_is_rejected() {
    let dir = log_with_checkpoints("forged", 3, 0);
    let receipts = read_receipts(&dir.join("receipts.jsonl")).expect("receipts");
    let checkpoints = read_checkpoints(&dir.join("checkpoints.jsonl")).expect("checkpoints");
    let other = SigningKey::generate().expect("keygen");
    assert_eq!(
        verify_checkpoints(&checkpoints, &receipts, &other.verifying_key()),
        Err(CheckpointBreak::BadSignature { checkpoint: 0 })
    );
}

#[test]
fn a_checkpoint_is_written_automatically_every_1000_receipts() {
    let dir = temp_dir("auto");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..1001 {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    let checkpoints = read_checkpoints(&dir.join("checkpoints.jsonl")).expect("read");
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].count, 1000);
    assert_eq!(check(&dir), Ok(()));
}
