//! Checkpoints make a cut-off log detectable. Written before the implementation.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use mohar_core::checkpoint::{CheckpointBreak, verify_checkpoints};
use mohar_core::store::{
    FileLog, OpenError, SignatureChecks, Stats, read_checkpoints, read_receipts, verify_log_with,
};
use mohar_core::{Action, BreakKind, Decision, Entry, SigningKey, parse_public_key};

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
            review: false,
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

#[test]
fn a_checkpoint_with_a_malformed_signature_is_rejected() {
    let dir = log_with_checkpoints("malformed-sig", 3, 0);
    let receipts = read_receipts(&dir.join("receipts.jsonl")).expect("receipts");
    let good = read_checkpoints(&dir.join("checkpoints.jsonl")).expect("checkpoints");
    let key =
        parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key")).expect("parse");
    for sig in [
        "",
        "rsa:00",
        "ed25519:zz",
        "ed25519:00",
        &good[0].sig[..good[0].sig.len() - 2],
    ] {
        let mut checkpoints = good.clone();
        checkpoints[0].sig = sig.to_string();
        assert_eq!(
            verify_checkpoints(&checkpoints, &receipts, &key),
            Err(CheckpointBreak::BadSignature { checkpoint: 0 }),
            "sig {sig:?}"
        );
    }
}

#[test]
fn a_checkpoint_over_an_empty_log_vouches_for_nothing_and_verifies() {
    let key = SigningKey::generate().expect("keygen");
    let log = mohar_core::Log::new(key.clone());
    let c = log
        .checkpoint("2026-10-14T15:00:00.000Z")
        .expect("checkpoint");
    assert_eq!(c.count, 0);
    assert_eq!(verify_checkpoints(&[c], &[], &key.verifying_key()), Ok(()));
}

fn verify_with(dir: &Path, checks: SignatureChecks) -> Result<Stats, OpenError> {
    let key =
        parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key")).expect("parse");
    verify_log_with(
        &dir.join("receipts.jsonl"),
        &dir.join("checkpoints.jsonl"),
        &[],
        &key,
        checks,
    )
}

/// `before` receipts, a checkpoint, then `after` more receipts with no checkpoint over them.
fn log_with_tail(name: &str, before: u64, after: u64) -> PathBuf {
    let dir = temp_dir(name);
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..before {
        log.append(entry(i)).expect("append");
    }
    log.checkpoint("2026-10-14T15:00:00.000Z")
        .expect("checkpoint");
    for i in before..before + after {
        log.append(entry(i)).expect("append");
    }
    dir
}

fn edit_line(dir: &Path, index: usize, edit: impl Fn(&mut serde_json::Value)) {
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut v: serde_json::Value = serde_json::from_str(&lines[index]).expect("receipt");
    edit(&mut v);
    lines[index] = v.to_string();
    fs::write(&path, lines.join("\n") + "\n").expect("write");
}

#[test]
fn trusting_checkpoints_verifies_an_intact_log_the_same_way() {
    let dir = log_with_tail("trust-ok", 5, 3);
    let every = verify_with(&dir, SignatureChecks::Every).expect("verifies");
    let trusting = verify_with(&dir, SignatureChecks::AfterLastCheckpoint).expect("verifies");
    assert_eq!(every, trusting);
}

#[test]
fn an_edit_before_the_checkpoint_is_caught_without_checking_its_signature() {
    let dir = log_with_tail("trust-edit", 5, 3);
    edit_line(&dir, 1, |v| v["action"]["target"] = "secrets.env".into());
    match verify_with(&dir, SignatureChecks::AfterLastCheckpoint) {
        Err(OpenError::Chain(b)) => assert_eq!((b.index, b.kind), (2, BreakKind::BrokenLink)),
        other => panic!("expected a broken link after the edited receipt, got {other:?}"),
    }
}

#[test]
fn an_edit_to_the_receipt_the_checkpoint_signs_is_caught() {
    let dir = log_with_tail("trust-head", 5, 0);
    edit_line(&dir, 4, |v| v["action"]["target"] = "secrets.env".into());
    assert!(matches!(
        verify_with(&dir, SignatureChecks::AfterLastCheckpoint),
        Err(OpenError::Checkpoint(CheckpointBreak::HeadMismatch {
            seq: 4,
            ..
        }))
    ));
}

#[test]
fn a_signature_swapped_before_the_checkpoint_breaks_the_chain() {
    // The hash of a receipt covers its signature, so even the signature can't be changed unseen.
    let dir = log_with_tail("trust-sig", 5, 3);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let other: serde_json::Value =
        serde_json::from_str(text.lines().nth(3).expect("line")).expect("receipt");
    edit_line(&dir, 2, |v| v["sig"] = other["sig"].clone());
    match verify_with(&dir, SignatureChecks::AfterLastCheckpoint) {
        Err(OpenError::Chain(b)) => assert_eq!((b.index, b.kind), (3, BreakKind::BrokenLink)),
        other => panic!("expected a broken link, got {other:?}"),
    }
}

#[test]
fn signatures_after_the_last_checkpoint_are_still_checked() {
    // One receipt after the checkpoint and nothing linking to it: only its own signature can catch a
    // change, and the first receipt after the checkpoint must not fall on the trusted side.
    let dir = log_with_tail("trust-tail", 5, 1);
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let other: serde_json::Value =
        serde_json::from_str(text.lines().nth(4).expect("line")).expect("receipt");
    edit_line(&dir, 5, |v| v["sig"] = other["sig"].clone());
    match verify_with(&dir, SignatureChecks::AfterLastCheckpoint) {
        Err(OpenError::Chain(b)) => assert_eq!((b.index, b.kind), (5, BreakKind::BadSignature)),
        other => panic!("expected a bad signature, got {other:?}"),
    }
}

#[test]
fn a_checkpoint_with_a_bad_signature_is_never_trusted() {
    let dir = log_with_tail("trust-forged", 5, 3);
    let path = dir.join("checkpoints.jsonl");
    let mut c: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&path).expect("read").trim()).expect("checkpoint");
    c["count"] = 8.into();
    fs::write(&path, c.to_string() + "\n").expect("write");
    assert!(matches!(
        verify_with(&dir, SignatureChecks::AfterLastCheckpoint),
        Err(OpenError::Checkpoint(CheckpointBreak::BadSignature {
            checkpoint: 0
        }))
    ));
}
