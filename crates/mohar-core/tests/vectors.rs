//! Test vectors for other implementations, regenerated from a fixed seed and compared byte for byte.
//!
//! Set MOHAR_WRITE_VECTORS=1 to rewrite spec/vectors/v1.json after an intentional format change.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use mohar_core::{Log, SigningKey, canonical_bytes, public_key_string, receipt_hash};
use serde_json::{Value, json};

mod common;
use common::{SEED, entries, hex};

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
