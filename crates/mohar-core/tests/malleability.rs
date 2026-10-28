//! Found by the `chain_mutation` fuzz target: a signature or key written in a different spelling of
//! the same bytes must not verify, or the same log has two valid encodings.
#![allow(clippy::expect_used)]

use mohar_core::checkpoint::verify_checkpoints;
use mohar_core::{
    Action, Decision, Entry, Log, SigningKey, parse_public_key, public_key_string, verify,
};

fn log_of(n: u64) -> (Log, SigningKey) {
    let key = SigningKey::from_seed(&[7; 32]);
    let mut log = Log::new(key.clone());
    for i in 0..n {
        log.append(Entry {
            ts: format!("2026-11-03T14:22:{:02}.000Z", i % 60),
            agent_id: "agent:fuzz/0001".into(),
            action: Action {
                capability: "fs.edit.tests".into(),
                tool: "Edit".into(),
                target: format!("tests/t{i}.rs"),
                args_sha256: "c41b77d0".into(),
            },
            decision: Decision {
                result: "allow".into(),
                level: 1,
                by: "score".into(),
                review: false,
            },
            verification: None,
        })
        .expect("append");
    }
    (log, key)
}

fn respell(sig: &str, f: impl Fn(&str) -> String) -> String {
    let (prefix, hex) = sig.split_at("ed25519:".len());
    format!("{prefix}{}", f(hex))
}

#[test]
fn an_uppercase_signature_on_the_last_receipt_does_not_verify() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    let last = r.last_mut().expect("five receipts");
    last.sig = respell(&last.sig, str::to_uppercase);
    assert!(verify(&r, &key.verifying_key()).is_err());
}

#[test]
fn an_uppercase_checkpoint_signature_does_not_verify() {
    let (log, key) = log_of(5);
    let mut c = log.checkpoint("2026-11-03T14:23:00.000Z").expect("sign");
    c.sig = respell(&c.sig, str::to_uppercase);
    assert!(verify_checkpoints(&[c], log.receipts(), &key.verifying_key()).is_err());
}

#[test]
fn a_public_key_must_be_lowercase_hex() {
    let key = SigningKey::from_seed(&[7; 32]).verifying_key();
    let lower = public_key_string(&key);
    assert!(parse_public_key(&lower).is_some());
    assert!(parse_public_key(&respell(&lower, str::to_uppercase)).is_none());
}

#[test]
fn an_outcome_with_a_field_the_format_does_not_define_does_not_parse() {
    let (log, _) = log_of(1);
    let mut outcome = serde_json::to_value(&log.receipts()[0]).expect("json");
    outcome["verification"] = serde_json::json!({
        "evidence_sha256": "5d41402a", "kind": "tests", "of": 0, "result": "pass"
    });
    assert!(serde_json::from_value::<mohar_core::Receipt>(outcome.clone()).is_ok());
    outcome["verification"]["reviewer"] = "human:7f3a09c2".into();
    assert!(serde_json::from_value::<mohar_core::Receipt>(outcome).is_err());
}
