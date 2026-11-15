//! A person who refuses an action and says the action itself was wrong (docs/design.md section 4, the
//! S1 row): it never ran, so it is minor on any capability, but it is evidence against the agent (#222).
#![allow(clippy::expect_used)]

use mohar_core::policy::{Capability, Risk};
use mohar_core::trust::{
    ASK_FIRST, Ledger, NEAR_MISS_PER_MILLE, Outcome, SUPERVISED, Severity, TRUSTED,
    review_per_mille,
};

const DAY: u64 = 86_400;
const A: &str = "agent:test/1";
const C: &str = "fs.edit.docs";

fn spec() -> Capability {
    Capability {
        risk: Risk::Low,
        reversible: true,
        ceiling: 2,
    }
}

fn pass(at: u64) -> Outcome {
    Outcome {
        at,
        passed: true,
        severity: Severity::S1,
        exercises_failure: false,
        related: vec![],
        verifier: "tests".into(),
    }
}

#[test]
fn a_wrong_refusal_is_a_failure_on_the_record() {
    let mut l = Ledger::new();
    l.record(A, C, &pass(0));
    l.refused_wrong(A, C, 0);
    assert_eq!(l.tally(A, C), (1, 1));
    assert_eq!(
        l.tally(A, "fs.edit.code"),
        (0, 0),
        "only on that capability"
    );
    assert_eq!(l.tally("agent:test/2", C), (0, 0), "only for that agent");
}

#[test]
fn wrong_refusals_keep_a_poor_agent_from_promotion() {
    // Thirty passes in a row promote to Supervised; with the eight refusals a 79% agent's careful
    // reviewer would have written, the same passes don't.
    let (mut with, mut without) = (Ledger::new(), Ledger::new());
    for i in 0..30 {
        with.record(A, C, &pass(i));
        without.record(A, C, &pass(i));
    }
    for i in 0..8 {
        with.refused_wrong(A, C, i);
    }
    assert_eq!(without.level(A, C, &spec(), 7 * DAY), SUPERVISED);
    assert_eq!(with.level(A, C, &spec(), 7 * DAY), ASK_FIRST);
}

#[test]
fn a_wrong_refusal_raises_review_sampling_like_a_near_miss() {
    let mut l = Ledger::new();
    l.refused_wrong(A, C, 0);
    assert_eq!(l.review_rate(A, C, TRUSTED), NEAR_MISS_PER_MILLE);
    assert_eq!(
        l.review_rate(A, "fs.edit.code", TRUSTED),
        review_per_mille(TRUSTED)
    );
}
#[test]
fn two_wrong_refusals_demote_nothing_and_the_third_in_fourteen_days_is_an_s2() {
    let high = Capability {
        risk: Risk::High,
        reversible: false,
        ceiling: 1,
    };
    let mut l = Ledger::new();
    for i in 0..40 {
        l.record(A, C, &pass(i));
    }
    assert_eq!(l.level(A, C, &high, 7 * DAY), SUPERVISED);
    // It never ran, so even on a high-risk irreversible capability a refusal is minor.
    l.refused_wrong(A, C, 7 * DAY);
    l.refused_wrong(A, C, 8 * DAY);
    assert_eq!(l.level(A, C, &high, 8 * DAY), SUPERVISED, "two are minor");
    assert!(!l.in_remediation(A, C));
    assert!(!l.is_suspended(A));
    l.refused_wrong(A, C, 21 * DAY);
    assert_eq!(
        l.level(A, C, &high, 21 * DAY),
        ASK_FIRST,
        "third within 14 days"
    );
    assert!(l.in_remediation(A, C));
    assert!(!l.is_suspended(A));
}

#[test]
fn a_plan_opened_by_refusals_asks_for_the_verifier_already_checking_the_capability() {
    let mut l = Ledger::new();
    l.record(A, C, &pass(0));
    for t in 1..=3 {
        l.refused_wrong(A, C, t);
    }
    let plan = l.plan(A, C).expect("plan");
    assert_eq!(plan.verifier, "tests");
    // With no outcome on record yet, only a person's review can end it.
    for t in 1..=3 {
        l.refused_wrong(A, "fs.edit.code", t);
    }
    assert_eq!(l.plan(A, "fs.edit.code").expect("plan").verifier, "human");
}
