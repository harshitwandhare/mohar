//! Behaviour of the receipt chain, written before the implementation.
#![allow(clippy::expect_used)]

use mohar_core::{Action, BreakKind, Decision, Entry, Log, SigningKey, verify};
use proptest::prelude::*;

fn entry(i: u64) -> Entry {
    Entry {
        ts: format!("2026-11-03T14:22:{:02}.000Z", i % 60),
        agent_id: "agent:test/7c1e".into(),
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
    }
}

fn log_of(n: u64) -> (Log, SigningKey) {
    let key = SigningKey::generate().unwrap_or_else(|e| panic!("keygen: {e}"));
    let mut log = Log::new(key.clone());
    for i in 0..n {
        log.append(entry(i))
            .unwrap_or_else(|e| panic!("append: {e}"));
    }
    (log, key)
}

#[test]
fn a_fresh_chain_verifies() {
    let (log, key) = log_of(5);
    assert_eq!(verify(log.receipts(), &key.verifying_key()), Ok(()));
}

#[test]
fn the_first_receipt_points_at_zeros_and_sequences_count_up() {
    let (log, _) = log_of(3);
    let r = log.receipts();
    assert_eq!(r[0].prev, format!("sha256:{}", "0".repeat(64)));
    assert_eq!(r.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[test]
fn editing_a_field_breaks_that_receipt() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r[2].decision.result = "deny".into();
    let err = verify(&r, &key.verifying_key()).expect_err("edit must be caught");
    assert_eq!((err.index, err.kind), (2, BreakKind::BadSignature));
}

#[test]
fn deleting_a_receipt_breaks_the_next_one() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r.remove(2);
    let err = verify(&r, &key.verifying_key()).expect_err("gap must be caught");
    assert_eq!(err.index, 2);
}

#[test]
fn swapping_two_receipts_is_caught() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r.swap(1, 3);
    let err = verify(&r, &key.verifying_key()).expect_err("swap must be caught");
    assert_eq!(err.index, 1);
}

#[test]
fn a_different_key_fails_on_the_first_receipt() {
    let (log, _) = log_of(3);
    let other = SigningKey::generate().unwrap_or_else(|e| panic!("keygen: {e}"));
    let err = verify(log.receipts(), &other.verifying_key()).expect_err("wrong key");
    assert_eq!((err.index, err.kind), (0, BreakKind::BadSignature));
}

#[test]
fn the_review_mark_is_signed_and_left_out_when_unset() {
    let key = SigningKey::generate().unwrap_or_else(|e| panic!("keygen: {e}"));
    let mut log = Log::new(key.clone());
    log.append(entry(0))
        .unwrap_or_else(|e| panic!("append: {e}"));
    let mut sampled = entry(1);
    sampled.decision.review = true;
    log.append(sampled)
        .unwrap_or_else(|e| panic!("append: {e}"));
    let r = log.receipts().to_vec();
    assert_eq!(verify(&r, &key.verifying_key()), Ok(()));
    let unset = serde_json::to_string(&r[0]).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !unset.contains("review"),
        "receipts from before sampling read the same: {unset}"
    );
    let set = serde_json::to_string(&r[1]).unwrap_or_else(|e| panic!("{e}"));
    assert!(set.contains(r#""review":true"#), "{set}");
    let back: mohar_core::Receipt = serde_json::from_str(&set).unwrap_or_else(|e| panic!("{e}"));
    assert!(back.decision.review);
    // Hiding that an action was picked for review, or claiming one was, breaks the signature.
    for (i, flip) in [(0, true), (1, false)] {
        let mut t = r.clone();
        t[i].decision.review = flip;
        let err = verify(&t, &key.verifying_key()).expect_err("flip must be caught");
        assert_eq!((err.index, err.kind), (i, BreakKind::BadSignature));
    }
}

#[test]
fn receipts_round_trip_through_json() {
    let (log, key) = log_of(4);
    let json = serde_json::to_string(log.receipts()).unwrap_or_else(|e| panic!("{e}"));
    let back: Vec<mohar_core::Receipt> =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(verify(&back, &key.verifying_key()), Ok(()));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// Changing any one character of a receipt's JSON either makes it unparseable or fails
    /// verification. No single edit slips through.
    #[test]
    fn any_single_character_change_is_caught(pos in 0usize..10_000, ch in proptest::char::range('!', '~')) {
        let (log, key) = log_of(3);
        let mut json = serde_json::to_string(&log.receipts()[1]).unwrap_or_else(|e| panic!("{e}"));
        let at = pos % json.len();
        prop_assume!(json.is_char_boundary(at) && json.is_char_boundary(at + 1));
        prop_assume!(json[at..at + 1] != ch.to_string());
        json.replace_range(at..at + 1, &ch.to_string());
        if let Ok(edited) = serde_json::from_str::<mohar_core::Receipt>(&json) {
            let mut r = log.receipts().to_vec();
            if edited != r[1] {
                r[1] = edited;
                prop_assert!(verify(&r, &key.verifying_key()).is_err());
            }
        }
    }
}

#[test]
fn a_receipt_with_a_malformed_signature_breaks_the_chain() {
    let (log, key) = log_of(2);
    let good = log.receipts().to_vec();
    let cut = &good[1].sig[..good[1].sig.len() - 2];
    for sig in ["", "rsa:00", "ed25519:zz", "ed25519:00", cut] {
        let mut receipts = good.clone();
        receipts[1].sig = sig.to_string();
        let err = verify(&receipts, &key.verifying_key()).expect_err("must break");
        assert_eq!(
            (err.index, err.kind),
            (1, BreakKind::BadSignature),
            "sig {sig:?}"
        );
    }
}
