//! Conformance vectors for spec/receipts-v1.md: logs that reach Level 2, logs that stop at Level 1 and
//! logs that reach no level, each with the level a verifier must report. `spec/vectors/check.py`
//! reads the same file and must agree on every case.
//!
//! Set MOHAR_WRITE_VECTORS=1 to rewrite spec/vectors/conformance-v1.json after an intentional change.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use ed25519_dalek::Signer;
use mohar_core::checkpoint::{Checkpoint, verify_checkpoints};
use mohar_core::store::{SignatureChecks, verify_dir};
use mohar_core::{
    Log, Receipt, SigningKey, canonical_bytes, parse_public_key, public_key_string, receipt_hash,
    verify,
};
use serde_json::{Value, json};

mod common;
use common::{SEED, entries, hex};

/// A second test-only seed, bytes 0x20..=0x3f: the key someone rewriting the log would use.
const OTHER_SEED: [u8; 32] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63,
];

const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn key_string(seed: &[u8; 32]) -> String {
    public_key_string(&SigningKey::from_seed(seed).verifying_key())
}

fn signature(seed: &[u8; 32], msg: &[u8]) -> String {
    let sig = ed25519_dalek::SigningKey::from_bytes(seed).sign(msg);
    format!("ed25519:{}", hex(&sig.to_bytes()))
}

/// Sign a receipt again after an edit, the way someone holding `seed` could.
fn resign(r: &mut Receipt, seed: &[u8; 32]) {
    r.sig.clear();
    r.sig = signature(seed, &canonical_bytes(r).expect("canonical"));
}

/// Sign a checkpoint's content with `seed`, whatever key signed it before.
fn resign_checkpoint(c: &mut Checkpoint, seed: &[u8; 32]) {
    c.sig.clear();
    c.sig = signature(seed, &serde_jcs::to_vec(c).expect("canonical"));
}

/// The four receipts of v1.json signed with `seed`, and checkpoints after the second and the fourth.
fn log(seed: &[u8; 32]) -> (Vec<Receipt>, Vec<Checkpoint>) {
    let mut log = Log::new(SigningKey::from_seed(seed));
    let mut checkpoints = Vec::new();
    for (i, e) in entries().into_iter().enumerate() {
        log.append(e).expect("append");
        if i % 2 == 1 {
            checkpoints.push(
                log.checkpoint("2026-11-03T15:00:00.000Z")
                    .expect("checkpoint"),
            );
        }
    }
    (log.receipts().to_vec(), checkpoints)
}

fn case(
    name: &str,
    about: &str,
    expect_level: u8,
    log_key: &[u8; 32],
    pinned_key: Option<&[u8; 32]>,
    receipts: &[Receipt],
    published: &[Checkpoint],
) -> Value {
    json!({
        "name": name,
        "about": about,
        "expect_level": expect_level,
        "log_key": key_string(log_key),
        "pinned_key": pinned_key.map(key_string),
        "receipts": receipts,
        "published_checkpoints": published,
    })
}

fn cases() -> Vec<Value> {
    let (good, checkpoints) = log(&SEED);
    let (other, other_checkpoints) = log(&OTHER_SEED);
    let a = &SEED;
    let b = &OTHER_SEED;

    let mut bad_sig = good.clone();
    // Flip the last hex digit of a signature: still well formed, no longer valid.
    let last = bad_sig[1].sig.pop().expect("sig");
    bad_sig[1].sig.push(if last == '0' { '1' } else { '0' });

    let mut edited = good.clone();
    edited[1].action.target = "release".into();

    let mut broken_link = good.clone();
    broken_link[2].prev = GENESIS.into();
    resign(&mut broken_link[2], a);

    let removed: Vec<Receipt> = [0, 1, 3].iter().map(|&i| good[i].clone()).collect();

    let mut uppercase = good.clone();
    uppercase[3].sig = uppercase[3]
        .sig
        .to_uppercase()
        .replace("ED25519:", "ed25519:");

    let mut unknown_version = good.clone();
    unknown_version[0].v = 2;
    resign(&mut unknown_version[0], a);
    for i in 1..unknown_version.len() {
        unknown_version[i].prev = receipt_hash(&unknown_version[i - 1]).expect("hash");
        resign(&mut unknown_version[i], a);
    }

    let mut rewritten_last = good.clone();
    if let Some(v) = rewritten_last[3].verification.as_mut() {
        v.result = "fail".into();
    }
    resign(&mut rewritten_last[3], a);

    let empty = Log::new(SigningKey::from_seed(a))
        .checkpoint("2026-11-03T13:00:00.000Z")
        .expect("checkpoint");

    let mut forged = checkpoints.clone();
    resign_checkpoint(&mut forged[1], b);

    let mut out = vec![
        case(
            "level-2",
            "Every receipt verifies against the pinned key, and the log still holds what both published checkpoints vouched for.",
            2,
            a,
            Some(a),
            &good,
            &checkpoints,
        ),
        case(
            "no-published-checkpoints",
            "A sound chain with a pinned key, but nothing outside the machine says how long the log was.",
            1,
            a,
            Some(a),
            &good,
            &[],
        ),
        case(
            "no-pinned-key",
            "A sound chain and published checkpoints, but the only key is the one in the log directory.",
            1,
            a,
            None,
            &good,
            &checkpoints,
        ),
        case(
            "tail-deleted",
            "The last two receipts were removed. What is left verifies, but a published checkpoint vouched for four.",
            1,
            a,
            Some(a),
            &good[..2],
            &checkpoints,
        ),
        case(
            "rewritten-with-another-key",
            "The log and its checkpoints were signed again with a different key, which replaced public.key. It verifies on its own terms, not against the pinned key.",
            1,
            b,
            Some(a),
            &other,
            &other_checkpoints,
        ),
        case(
            "rewritten-after-an-empty-checkpoint",
            "The log was signed again with a different key. The only published checkpoint is the pinned key's, from when the log was empty, so it vouches for nothing; the receipts still have to verify against the pinned key.",
            1,
            b,
            Some(a),
            &other,
            std::slice::from_ref(&empty),
        ),
        case(
            "checkpoint-from-another-key",
            "The latest published checkpoint was signed by a key other than the pinned one.",
            1,
            a,
            Some(a),
            &good,
            &forged,
        ),
        case(
            "last-receipt-rewritten",
            "The key holder changed the last outcome from pass to fail and signed it again. The chain verifies, but the receipt at the published head is not the one signed for.",
            1,
            a,
            Some(a),
            &rewritten_last,
            &checkpoints,
        ),
        case(
            "bad-signature",
            "The signature on receipt 1 has one hex digit changed.",
            0,
            a,
            Some(a),
            &bad_sig,
            &checkpoints,
        ),
        case(
            "edited-without-signing",
            "Receipt 1's target was changed and its old signature kept.",
            0,
            a,
            Some(a),
            &edited,
            &checkpoints,
        ),
        case(
            "broken-link",
            "Receipt 2 names the genesis hash as prev and is signed with the right key.",
            0,
            a,
            Some(a),
            &broken_link,
            &checkpoints,
        ),
        case(
            "receipt-removed",
            "Receipt 2 was removed from the middle, so the receipt at position 2 says seq 3.",
            0,
            a,
            Some(a),
            &removed,
            &checkpoints,
        ),
        case(
            "uppercase-hex-signature",
            "Receipt 3's signature is written in uppercase hex. The bytes are the same, but only lowercase is accepted, so each receipt has one encoding.",
            0,
            a,
            Some(a),
            &uppercase,
            &checkpoints,
        ),
        case(
            "unknown-version",
            "Receipt 0 says v 2, and the chain is rebuilt and signed after it.",
            0,
            a,
            Some(a),
            &unknown_version,
            &checkpoints,
        ),
        unsigned_field(&good, &checkpoints, "approved_by", json!("human:7f3a09c2")),
        unsigned_field(&good, &checkpoints, "verification", Value::Null),
        unsigned_field(
            &good,
            &checkpoints,
            "decision",
            json!({"by": "gate", "level": 0, "result": "escalate", "review": false}),
        ),
    ];
    out.extend(segment_cases(&good, &checkpoints));
    out
}

/// The 20-digit name of a segment whose first receipt is `start`.
fn seg(start: u64) -> String {
    format!("{start:020}.jsonl")
}

/// A rotated log (spec section 7): `segments` are (file name, receipts) under segments/, `receipts` is
/// receipts.jsonl, `local` is the log's own checkpoints.jsonl.
#[allow(clippy::too_many_arguments)]
fn segmented(
    name: &str,
    about: &str,
    expect_level: u8,
    segments: &[(String, &[Receipt])],
    receipts: &[Receipt],
    local: &[Checkpoint],
    published: &[Checkpoint],
) -> Value {
    let mut c = case(
        name,
        about,
        expect_level,
        &SEED,
        Some(&SEED),
        receipts,
        published,
    );
    c["segments"] = segments
        .iter()
        .map(|(n, r)| json!({"name": n, "receipts": r}))
        .collect();
    c["local_checkpoints"] = json!(local);
    c
}

/// `good` has four receipts; `checkpoints` vouch for 2 and 4 of them.
fn segment_cases(good: &[Receipt], checkpoints: &[Checkpoint]) -> Vec<Value> {
    let (c2, c4) = (&checkpoints[0], &checkpoints[1]);
    let mut conflicting = c2.clone();
    conflicting.head = receipt_hash(&good[0]).expect("hash");
    resign_checkpoint(&mut conflicting, &SEED);
    vec![
        segmented(
            "segments-pinned-and-published",
            "Receipts 0 and 1 were closed into a segment behind the checkpoint at 2; receipts.jsonl holds 2 and 3. The chain runs on across the files.",
            2,
            &[(seg(0), &good[..2])],
            &good[2..],
            &[c2.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
        segmented(
            "segments-all-archived",
            "Every closed segment was archived, so receipts.jsonl alone remains. It starts at its first receipt, 2, where a signed checkpoint vouches for the log.",
            2,
            &[],
            &good[2..],
            &[c2.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
        segmented(
            "segments-oldest-archived-without-checkpoint",
            "Every closed segment was archived and no checkpoint vouches for the log at 2, where what remains starts.",
            0,
            &[],
            &good[2..],
            std::slice::from_ref(c4),
            std::slice::from_ref(c4),
        ),
        segmented(
            "segment-not-closed",
            "The segment ends after 2 receipts but no checkpoint has count 2.",
            0,
            &[(seg(0), &good[..2])],
            &good[2..],
            std::slice::from_ref(c4),
            std::slice::from_ref(c4),
        ),
        segmented(
            "segment-missing-between",
            "The segment holding receipt 2 is gone: the one before ends at 2, the next is named 3.",
            0,
            &[(seg(0), &good[..2]), (seg(3), &good[3..])],
            &[],
            &[c2.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
        segmented(
            "segment-named-at-the-wrong-start",
            "The receipts run on unbroken, but the second segment is named 3 while the first ends at 2, so its name and its content disagree.",
            0,
            &[(seg(0), &good[..2]), (seg(3), &good[2..])],
            &[],
            &[c2.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
        segmented(
            "segments-conflicting-checkpoints",
            "Every closed segment was archived, and two checkpoints signed with the log's key vouch for different heads at 2, where what remains starts.",
            0,
            &[],
            &good[2..],
            &[c2.clone(), conflicting.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
        segmented(
            "segment-misnamed",
            "The segment is named 0.jsonl instead of 20 digits, so a verifier can't tell where it sits.",
            0,
            &[("0.jsonl".to_string(), &good[..2])],
            &good[2..],
            &[c2.clone(), c4.clone()],
            std::slice::from_ref(c4),
        ),
    ]
}

/// A key added to receipt 1 after it was signed. A key the format doesn't define, or an optional one
/// spelled out as false or null, would ride along under a signature that never covered it, so each fails.
fn unsigned_field(
    good: &[Receipt],
    checkpoints: &[Checkpoint],
    field: &str,
    value: Value,
) -> Value {
    let (name, about) = match field {
        "verification" => (
            "null-verification-added",
            "Receipt 1 says \"verification\": null, added after it was signed. Absent optional fields are left out, never written as null.",
        ),
        "decision" => (
            "false-review-added",
            "Receipt 1's decision says \"review\": false, added after it was signed. review is written only when true.",
        ),
        _ => (
            "unsigned-field-added",
            "Receipt 1 carries a field the format doesn't define, added after it was signed.",
        ),
    };
    let mut c = case(name, about, 0, &SEED, Some(&SEED), good, checkpoints);
    c["receipts"][1][field] = value;
    c
}

/// The level a log reaches, worked out with the Rust verifier.
fn level(case: &Value) -> u8 {
    if case.get("segments").is_some() {
        return level_on_disk(case);
    }
    let Ok(receipts) = serde_json::from_value::<Vec<Receipt>>(case["receipts"].clone()) else {
        return 0;
    };
    let Some(log_key) = case["log_key"].as_str().and_then(parse_public_key) else {
        return 0;
    };
    if verify(&receipts, &log_key).is_err() {
        return 0;
    }
    let Some(pinned) = case["pinned_key"].as_str().and_then(parse_public_key) else {
        return 1;
    };
    let Ok(published) =
        serde_json::from_value::<Vec<Checkpoint>>(case["published_checkpoints"].clone())
    else {
        return 1;
    };
    if verify(&receipts, &pinned).is_err()
        || published.is_empty()
        || verify_checkpoints(&published, &receipts, &pinned).is_err()
    {
        return 1;
    }
    2
}

/// Write a rotated case out as a log directory and verify it the way `mohar verify` does.
fn level_on_disk(case: &Value) -> u8 {
    let dir = std::env::temp_dir().join(format!(
        "mohar-conf-{}-{}",
        case["name"].as_str().expect("name"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("segments")).expect("mkdir");
    let lines = |v: &Value| -> String {
        v.as_array()
            .expect("array")
            .iter()
            .map(|x| {
                x.to_string()
                    + "
"
            })
            .collect()
    };
    for s in case["segments"].as_array().expect("segments") {
        let name = s["name"].as_str().expect("name");
        std::fs::write(dir.join("segments").join(name), lines(&s["receipts"])).expect("segment");
    }
    std::fs::write(dir.join("receipts.jsonl"), lines(&case["receipts"])).expect("receipts");
    std::fs::write(
        dir.join("checkpoints.jsonl"),
        lines(&case["local_checkpoints"]),
    )
    .expect("local");
    std::fs::write(
        dir.join("published.jsonl"),
        lines(&case["published_checkpoints"]),
    )
    .expect("published");
    let key = |k: &str| case[k].as_str().and_then(parse_public_key);
    let Some(log_key) = key("log_key") else {
        return 0;
    };
    if verify_dir(&dir, &[], &log_key, SignatureChecks::Every, None).is_err() {
        return 0;
    }
    let Some(pinned) = key("pinned_key") else {
        return 1;
    };
    let published = dir.join("published.jsonl");
    let none_published = case["published_checkpoints"]
        .as_array()
        .is_none_or(|a| a.is_empty());
    if none_published
        || verify_dir(&dir, &[&published], &pinned, SignatureChecks::Every, None).is_err()
    {
        return 1;
    }
    2
}

fn build() -> Value {
    json!({
        "format": "mohar receipts v1 conformance",
        "spec": "spec/receipts-v1.md, spec version 1.1.0",
        "notes": "Seeds are bytes 0x00..0x1f (the log's key) and 0x20..0x3f (another key), for testing only. Each case is a log: log_key is public.key in the log directory, pinned_key is the key the verifier was given some other way (null if none), published_checkpoints were kept outside the machine. A rotated log also has segments (file name under segments/ and its receipts, oldest first) and local_checkpoints (checkpoints.jsonl in the log directory); receipts is then receipts.jsonl. A verifier must report expect_level. Level 3 has no cases yet.",
        "cases": cases(),
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/conformance-v1.json")
}

#[test]
fn conformance_vectors_match_the_published_file() {
    let built = serde_json::to_string_pretty(&build()).expect("json") + "\n";
    if std::env::var_os("MOHAR_WRITE_VECTORS").is_some() {
        std::fs::write(path(), &built).expect("write");
    }
    let published = std::fs::read_to_string(path())
        .expect("spec/vectors/conformance-v1.json is missing; run with MOHAR_WRITE_VECTORS=1");
    assert_eq!(
        published.replace("\r\n", "\n"),
        built,
        "conformance vectors drifted from the implementation"
    );
}

#[test]
fn the_rust_verifier_reaches_the_expected_level_on_every_case() {
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(path()).expect("read")).expect("parse");
    let cases = v["cases"].as_array().expect("cases");
    for c in cases {
        assert_eq!(
            Some(u64::from(level(c))),
            c["expect_level"].as_u64(),
            "case {}",
            c["name"]
        );
    }
    for want in 0..=2 {
        assert!(
            cases.iter().any(|c| c["expect_level"] == want),
            "no case expects level {want}"
        );
    }
}
