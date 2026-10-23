//! Behaviour of the streaming verifier, written before the implementation. Each case mirrors one in
//! `chain.rs` and must give the same answer as the slice-based `verify`.
#![allow(clippy::expect_used)]

use mohar_core::{
    Action, BreakKind, ChainBreak, ChainVerifier, Decision, Entry, Log, Receipt, SigningKey,
    receipt_hash, verify,
};

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
        },
        verification: None,
    }
}

fn log_of(n: u64) -> (Log, SigningKey) {
    let key = SigningKey::generate().expect("keygen");
    let mut log = Log::new(key.clone());
    for i in 0..n {
        log.append(entry(i)).expect("append");
    }
    (log, key)
}

/// Push every receipt through a streaming verifier, stopping at the first break.
fn stream(receipts: &[Receipt], key: &SigningKey) -> Result<(), ChainBreak> {
    let vk = key.verifying_key();
    let mut chain = ChainVerifier::new(&vk);
    receipts.iter().try_for_each(|r| chain.push(r))
}

fn assert_same_as_slice_verify(receipts: &[Receipt], key: &SigningKey) -> Result<(), ChainBreak> {
    let streamed = stream(receipts, key);
    assert_eq!(streamed, verify(receipts, &key.verifying_key()));
    streamed
}

#[test]
fn a_fresh_chain_verifies_one_receipt_at_a_time() {
    let (log, key) = log_of(5);
    assert_eq!(assert_same_as_slice_verify(log.receipts(), &key), Ok(()));
}

#[test]
fn an_empty_chain_verifies() {
    let (log, key) = log_of(0);
    assert_eq!(assert_same_as_slice_verify(log.receipts(), &key), Ok(()));
}

#[test]
fn editing_a_field_breaks_that_receipt() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r[2].decision.result = "deny".into();
    let err = assert_same_as_slice_verify(&r, &key).expect_err("edit must be caught");
    assert_eq!((err.index, err.kind), (2, BreakKind::BadSignature));
}

#[test]
fn deleting_a_receipt_breaks_the_next_one() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r.remove(2);
    let err = assert_same_as_slice_verify(&r, &key).expect_err("deletion must be caught");
    assert_eq!(err.index, 2);
}

#[test]
fn reordering_receipts_is_caught() {
    let (log, key) = log_of(5);
    let mut r = log.receipts().to_vec();
    r.swap(1, 3);
    let err = assert_same_as_slice_verify(&r, &key).expect_err("reorder must be caught");
    assert_eq!(err.index, 1);
}

#[test]
fn a_wrong_prev_hash_is_a_broken_link() {
    // The receipt keeps a valid signature of its own, so only the link check can catch it. This is
    // the case that fails if the prev-hash comparison is removed from the streaming verifier.
    let (log, key) = log_of(1);
    let mut chain = log.receipts().to_vec();
    let forged = {
        let mut other = Log::new(key.clone());
        other.append(entry(99)).expect("append");
        let mut e = entry(1);
        e.action.target = "elsewhere".into();
        other.append(e).expect("append");
        other.receipts()[1].clone()
    };
    chain.push(forged);
    let err = assert_same_as_slice_verify(&chain, &key).expect_err("link must be checked");
    assert_eq!((err.index, err.kind), (1, BreakKind::BrokenLink));
}

#[test]
fn a_receipt_signed_by_another_key_is_rejected() {
    let (log, _) = log_of(3);
    let other = SigningKey::generate().expect("keygen");
    let err = assert_same_as_slice_verify(log.receipts(), &other).expect_err("wrong key");
    assert_eq!((err.index, err.kind), (0, BreakKind::BadSignature));
}

#[test]
fn an_unknown_version_is_rejected() {
    let (log, key) = log_of(2);
    let mut r = log.receipts().to_vec();
    r[1].v = 2;
    let err = assert_same_as_slice_verify(&r, &key).expect_err("version");
    assert_eq!((err.index, err.kind), (1, BreakKind::UnknownVersion));
}

#[test]
fn a_rejected_receipt_leaves_the_verifier_where_it_was() {
    let (log, key) = log_of(3);
    let vk = key.verifying_key();
    let mut chain = ChainVerifier::new(&vk);
    chain.push(&log.receipts()[0]).expect("first");
    let mut bad = log.receipts()[1].clone();
    bad.action.target = "tampered".into();
    assert!(chain.push(&bad).is_err());
    assert_eq!(chain.count(), 1);
    // The genuine receipt is still accepted afterwards.
    chain.push(&log.receipts()[1]).expect("second");
    chain.push(&log.receipts()[2]).expect("third");
    assert_eq!(chain.count(), 3);
    assert_eq!(
        chain.head(),
        receipt_hash(&log.receipts()[2]).expect("hash")
    );
}

#[test]
fn the_verifier_holds_no_per_receipt_state() {
    // Structural: a verifier is a key reference, one hash and one counter. A Vec of receipts would
    // make it at least 24 bytes larger and, more to the point, would not be a fixed size.
    assert!(std::mem::size_of::<ChainVerifier<'_>>() <= 64);

    let (log, key) = log_of(200);
    let vk = key.verifying_key();
    let mut chain = ChainVerifier::new(&vk);
    let head_len = chain.head().len();
    for r in log.receipts() {
        chain.push(r).expect("push");
        assert_eq!(chain.head().len(), head_len);
    }
    assert_eq!(chain.count(), 200);
}
