//! Shared fixtures: a fixed key and a small, deterministic log.
#![allow(dead_code)]

use mohar_core::{Action, Decision, Entry, Log, SigningKey, VerifyingKey};

pub const SEED: [u8; 32] = [7; 32];

pub fn key() -> SigningKey {
    SigningKey::from_seed(&SEED)
}

pub fn public() -> VerifyingKey {
    key().verifying_key()
}

pub fn entry(i: u64) -> Entry {
    Entry {
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
        },
    }
}

/// A valid log of `n` receipts, identical on every call.
pub fn log_of(n: u64) -> Log {
    let mut log = Log::new(key());
    for i in 0..n {
        if log.append(entry(i)).is_err() {
            unreachable!("appending to a fresh in-memory log cannot fail");
        }
    }
    log
}
