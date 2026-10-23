//! Test vectors for other implementations, regenerated from a fixed seed and compared byte for byte.
//!
//! Set MOHAR_WRITE_VECTORS=1 to rewrite spec/vectors/v1.json after an intentional format change.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use mohar_core::{
    Action, Decision, Entry, Log, SigningKey, canonical_bytes, public_key_string, receipt_hash,
};
use serde_json::{Value, json};

/// Test-only seed: bytes 0x00..=0x1f. Never use it for anything real.
const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn entries() -> Vec<Entry> {
    let action = |capability: &str, tool: &str, target: &str, args: &str| Action {
        capability: capability.into(),
        tool: tool.into(),
        target: target.into(),
        args_sha256: args.into(),
    };
    let decision = |result: &str, level: u8, by: &str| Decision {
        result: result.into(),
        level,
        by: by.into(),
    };
    vec![
        Entry {
            ts: "2026-11-03T14:22:07.311Z".into(),
            agent_id: "agent:claude-code/host-4b1d/7c1e".into(),
            action: action(
                "fs.edit.tests",
                "Edit",
                "tests/test_receipts.rs",
                "c41b77d0",
            ),
            decision: decision("allow", 1, "score"),
            verification: None,
        },
        Entry {
            ts: "2026-11-03T14:22:09.020Z".into(),
            agent_id: "agent:claude-code/host-4b1d/7c1e".into(),
            action: action("git.push.main", "Bash", "main", "9a01e5f3"),
            decision: decision("escalate", 0, "gate"),
            verification: None,
        },
        Entry {
            ts: "2026-11-03T14:23:41.555Z".into(),
            agent_id: "agent:claude-code/host-4b1d/7c1e".into(),
            action: action("git.push.main", "Bash", "main", "9a01e5f3"),
            decision: decision("allow", 0, "human"),
            verification: None,
        },
    ]
}

fn build() -> Value {
    let key = SigningKey::from_seed(&SEED);
    let mut log = Log::new(key.clone());
    for e in entries() {
        log.append(e).expect("append");
    }
    let receipts: Vec<Value> = log
        .receipts()
        .iter()
        .map(|r| {
            json!({
                "receipt": r,
                "canonical_hex": hex(&canonical_bytes(r).expect("canonical")),
                "sha256": receipt_hash(r).expect("hash"),
            })
        })
        .collect();
    let checkpoint = log
        .checkpoint("2026-11-03T15:00:00.000Z")
        .expect("checkpoint");
    json!({
        "format": "mohar receipts v1",
        "notes": "Seed is bytes 0x00..0x1f, for testing only. Receipts are signed with Ed25519 over the RFC 8785 canonical JSON without sig; prev is the SHA-256 of the previous receipt's canonical JSON with sig. The first prev is sha256: followed by 64 zeros. The checkpoint signs count, head and ts the same way.",
        "seed_hex": hex(&SEED),
        "public_key": public_key_string(&key.verifying_key()),
        "receipts": receipts,
        "checkpoint": checkpoint,
    })
}

#[test]
fn vectors_match_the_published_file() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v1.json");
    let built = serde_json::to_string_pretty(&build()).expect("json") + "\n";
    if std::env::var_os("MOHAR_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, &built).expect("write");
    }
    let published = std::fs::read_to_string(&path)
        .expect("spec/vectors/v1.json is missing; run with MOHAR_WRITE_VECTORS=1");
    assert_eq!(
        published.replace("\r\n", "\n"),
        built,
        "test vectors drifted from the implementation"
    );
}

#[test]
fn published_vectors_verify_with_only_the_public_key() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v1.json");
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("parse");
    let key = mohar_core::parse_public_key(v["public_key"].as_str().expect("key")).expect("key");
    let receipts: Vec<mohar_core::Receipt> = v["receipts"]
        .as_array()
        .expect("array")
        .iter()
        .map(|r| serde_json::from_value(r["receipt"].clone()).expect("receipt"))
        .collect();
    assert_eq!(mohar_core::verify(&receipts, &key), Ok(()));
    let checkpoint: mohar_core::checkpoint::Checkpoint =
        serde_json::from_value(v["checkpoint"].clone()).expect("checkpoint");
    assert_eq!(
        mohar_core::checkpoint::verify_checkpoints(&[checkpoint], &receipts, &key),
        Ok(())
    );
}
