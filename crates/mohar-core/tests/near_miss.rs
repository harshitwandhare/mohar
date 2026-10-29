//! After a near miss, review sampling on that capability rises to 50% for the next 20 allowed actions
//! (docs/design.md section 4, the S0 row).
#![allow(clippy::expect_used)]

use mohar_core::policy::{Capability, Risk};
use mohar_core::trust::{
    Ledger, NEAR_MISS_ACTIONS, NEAR_MISS_PER_MILLE, Outcome, SUPERVISED, Severity, TRUSTED,
    review_per_mille, sampled_at, sampled_for_review,
};

const DAY: u64 = 86_400;
const A: &str = "agent:test/1";
const C: &str = "fs.edit.docs";

#[test]
fn a_near_miss_raises_the_rate_for_twenty_allowed_actions_then_it_falls_back() {
    let mut l = Ledger::new();
    assert_eq!(
        l.review_rate(A, C, SUPERVISED),
        review_per_mille(SUPERVISED)
    );
    l.near_miss(A, C);
    for i in 0..NEAR_MISS_ACTIONS {
        assert_eq!(
            l.review_rate(A, C, SUPERVISED),
            NEAR_MISS_PER_MILLE,
            "action {i}"
        );
        assert_eq!(
            l.review_rate(A, C, TRUSTED),
            NEAR_MISS_PER_MILLE,
            "at any level"
        );
        l.count_allowed(A, C);
    }
    // Action 21.
    assert_eq!(
        l.review_rate(A, C, SUPERVISED),
        review_per_mille(SUPERVISED)
    );
    assert_eq!(l.review_rate(A, C, TRUSTED), review_per_mille(TRUSTED));
    l.count_allowed(A, C);
    assert_eq!(
        l.review_rate(A, C, SUPERVISED),
        review_per_mille(SUPERVISED)
    );
}

#[test]
fn the_rise_is_per_agent_and_per_capability() {
    let mut l = Ledger::new();
    l.near_miss(A, C);
    assert_eq!(l.review_rate("agent:test/2", C, SUPERVISED), 200);
    assert_eq!(l.review_rate(A, "fs.edit.code", SUPERVISED), 200);
    // Allowed actions elsewhere don't use up the raised ones.
    for _ in 0..100 {
        l.count_allowed(A, "fs.edit.code");
    }
    assert_eq!(l.review_rate(A, C, SUPERVISED), NEAR_MISS_PER_MILLE);
}

#[test]
fn another_near_miss_starts_the_twenty_again() {
    let mut l = Ledger::new();
    l.near_miss(A, C);
    for _ in 0..15 {
        l.count_allowed(A, C);
    }
    l.near_miss(A, C);
    for _ in 0..NEAR_MISS_ACTIONS {
        assert_eq!(l.review_rate(A, C, SUPERVISED), NEAR_MISS_PER_MILLE);
        l.count_allowed(A, C);
    }
    assert_eq!(l.review_rate(A, C, SUPERVISED), 200);
}

#[test]
fn a_near_miss_changes_no_level_and_adds_no_evidence() {
    let spec = Capability {
        risk: Risk::Low,
        reversible: true,
        ceiling: 2,
    };
    let pass = Outcome {
        at: 0,
        passed: true,
        severity: Severity::S1,
        exercises_failure: false,
        related: vec![],
        verifier: "tests".into(),
    };
    let (mut with, mut without) = (Ledger::new(), Ledger::new());
    for _ in 0..30 {
        with.record(A, C, &pass);
        without.record(A, C, &pass);
    }
    for _ in 0..10 {
        with.near_miss(A, C);
    }
    for day in [7, 14, 21] {
        assert_eq!(
            with.level(A, C, &spec, day * DAY),
            without.level(A, C, &spec, day * DAY)
        );
    }
    assert!(!with.in_remediation(A, C));
}

#[test]
fn sampling_at_fifty_percent_draws_half_of_the_actions() {
    // 20,000 draws per seed: the standard deviation at 50% is about 71, so the bounds are seven wide.
    let n = 20_000u64;
    for k in 0u8..4 {
        let seed = [k.wrapping_mul(53).wrapping_add(3); 32];
        let hits = (0..n)
            .filter(|&seq| sampled_at(&seed, seq, NEAR_MISS_PER_MILLE))
            .count();
        assert!((9_500..=10_500).contains(&hits), "seed {k}: {hits} of {n}");
    }
}

#[test]
fn sampling_by_rate_matches_sampling_by_level() {
    let seed = [5u8; 32];
    for seq in 0..5_000 {
        for level in 0..=2 {
            assert_eq!(
                sampled_at(&seed, seq, review_per_mille(level)),
                sampled_for_review(&seed, seq, level)
            );
        }
    }
}

#[test]
fn the_twenty_raised_actions_then_the_next_ones_sample_at_the_right_rates() {
    // Many agents, each with one near miss: across all of them, the first 20 allowed actions are drawn
    // at 50% and action 21 onward at the level's 20%.
    let seed = [11u8; 32];
    let mut l = Ledger::new();
    let (mut raised, mut after) = (0u64, 0u64);
    let mut seq = 0u64;
    let agents = 500;
    for a in 0..agents {
        let agent = format!("agent:test/{a}");
        l.near_miss(&agent, C);
        for i in 0..40 {
            let hit = sampled_at(&seed, seq, l.review_rate(&agent, C, SUPERVISED));
            l.count_allowed(&agent, C);
            seq += 1;
            if hit && i < 20 {
                raised += 1;
            } else if hit {
                after += 1;
            }
        }
    }
    // 10,000 draws on each side: about 5,000 (sd 50) and 2,000 (sd 40).
    assert!((4_700..=5_300).contains(&raised), "{raised}");
    assert!((1_760..=2_240).contains(&after), "{after}");
}
