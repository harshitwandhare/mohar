//! The fixed key and entries both vector files are built from.
#![allow(dead_code)]

use mohar_core::{Action, Decision, Entry, Verification};

/// Test-only seed: bytes 0x00..=0x1f. Never use it for anything real.
pub const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn entries() -> Vec<Entry> {
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
        review: false,
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
        // The outcome of the first decision: its tests passed. It repeats that decision and names it.
        Entry {
            ts: "2026-11-03T14:25:02.870Z".into(),
            agent_id: "agent:claude-code/host-4b1d/7c1e".into(),
            action: action(
                "fs.edit.tests",
                "Edit",
                "tests/test_receipts.rs",
                "c41b77d0",
            ),
            decision: decision("allow", 1, "score"),
            verification: Some(Verification {
                evidence_sha256: "5d41402abc4b2a76b9719d911017c592ae8a2f3c1d2e6b0a4f7c9e1d3b5a7c90"
                    .into(),
                kind: "tests".into(),
                of: 0,
                result: "pass".into(),
            }),
        },
    ]
}
