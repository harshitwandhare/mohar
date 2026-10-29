//! Remediation plans (docs/design.md section 4): a named verifier, an exit condition and a deadline.
#![allow(clippy::expect_used)]

use mohar_core::policy::{Capability, Risk};
use mohar_core::trust::{
    ASK_FIRST, Ledger, Outcome, REMEDIATION_DAYS, REMEDIATION_PASSES, SUPERVISED, Severity,
};

const DAY: u64 = 86_400;
const A: &str = "agent:test/1";
const C: &str = "fs.edit.code";

fn code() -> Capability {
    Capability {
        risk: Risk::Medium,
        reversible: true,
        ceiling: 2,
    }
}

fn outcome(at: u64, passed: bool, verifier: &str) -> Outcome {
    Outcome {
        at,
        passed,
        severity: Severity::S2,
        exercises_failure: false,
        related: vec![],
        verifier: verifier.into(),
    }
}

/// A ledger where the agent reached Supervised on C and then failed meaningfully at day 8, caught by
/// the `tests` verifier.
fn demoted() -> Ledger {
    let mut l = Ledger::new();
    for _ in 0..40 {
        l.record(A, C, &outcome(0, true, "tests"));
    }
    assert_eq!(l.level(A, C, &code(), 7 * DAY), SUPERVISED);
    l.record(A, C, &outcome(8 * DAY, false, "tests"));
    l
}

/// The exit condition met: five passes from `verifier`, the last one exercising the failure.
fn finish(l: &mut Ledger, at: u64, verifier: &str) {
    for i in 0..REMEDIATION_PASSES {
        let mut o = outcome(at + u64::from(i), true, verifier);
        o.exercises_failure = i + 1 == REMEDIATION_PASSES;
        l.record(A, C, &o);
    }
}

#[test]
fn a_demotion_opens_a_plan_naming_the_verifier_that_caught_it_and_a_deadline() {
    let l = demoted();
    let plan = l.plan(A, C).expect("a plan");
    assert_eq!(plan.verifier, "tests");
    assert_eq!(plan.passes_left, REMEDIATION_PASSES);
    assert!(plan.must_exercise);
    assert_eq!(plan.deadline, 8 * DAY + REMEDIATION_DAYS * DAY);
}

#[test]
fn only_passes_from_the_named_verifier_count_toward_the_exit() {
    let mut l = demoted();
    finish(&mut l, 9 * DAY, "lint");
    assert!(
        l.in_remediation(A, C),
        "another verifier's passes don't end it"
    );
    assert_eq!(l.plan(A, C).expect("plan").passes_left, REMEDIATION_PASSES);
    finish(&mut l, 10 * DAY, "tests");
    assert!(!l.in_remediation(A, C));
}

#[test]
fn passes_after_the_deadline_do_not_end_the_plan_and_the_level_stays() {
    let mut l = demoted();
    let deadline = l.plan(A, C).expect("plan").deadline;
    assert!(l.overdue(deadline).is_empty(), "due, not yet overdue");
    finish(&mut l, deadline + 1, "tests");
    assert!(l.in_remediation(A, C));
    assert_eq!(
        l.overdue(deadline + 1),
        vec![(A.to_string(), C.to_string())]
    );
    // However strong the record, an overdue plan holds the capability where it was dropped to.
    for _ in 0..200 {
        l.record(A, C, &outcome(deadline + 2, true, "tests"));
    }
    assert_eq!(l.level(A, C, &code(), deadline + 60 * DAY), ASK_FIRST);
}

#[test]
fn passes_on_the_deadline_itself_still_count() {
    let mut l = demoted();
    let deadline = l.plan(A, C).expect("plan").deadline;
    finish(
        &mut l,
        deadline - u64::from(REMEDIATION_PASSES) + 1,
        "tests",
    );
    assert!(!l.in_remediation(A, C));
}

#[test]
fn a_person_can_extend_an_overdue_plan_and_then_it_can_finish() {
    let mut l = demoted();
    let deadline = l.plan(A, C).expect("plan").deadline;
    assert!(l.extend_remediation(A, C, deadline + 10 * DAY));
    assert!(l.overdue(deadline + 1).is_empty());
    finish(&mut l, deadline + DAY, "tests");
    assert!(!l.in_remediation(A, C));
    assert!(
        !l.extend_remediation(A, C, deadline + 20 * DAY),
        "nothing left to extend"
    );
}

#[test]
fn an_extension_can_only_move_the_deadline_later() {
    let mut l = demoted();
    let deadline = l.plan(A, C).expect("plan").deadline;
    assert!(!l.extend_remediation(A, C, deadline - 1));
    assert_eq!(l.plan(A, C).expect("plan").deadline, deadline);
}

#[test]
fn a_serious_failure_opens_plans_on_the_shared_scope_with_the_same_verifier() {
    let mut l = Ledger::new();
    let mut o = outcome(DAY, false, "replay");
    o.severity = Severity::S3;
    o.related = vec!["db.seed".into()];
    l.record(A, "db.migrate", &o);
    let own = l.plan(A, "db.migrate").expect("own plan");
    let shared = l.plan(A, "db.seed").expect("shared plan");
    assert_eq!(
        (own.verifier.as_str(), shared.verifier.as_str()),
        ("replay", "replay")
    );
    assert!(own.must_exercise);
    assert!(!shared.must_exercise, "the shared scope didn't fail itself");
    assert_eq!(shared.deadline, own.deadline);
}

#[test]
fn no_plan_without_a_demotion() {
    let mut l = Ledger::new();
    let mut o = outcome(DAY, false, "tests");
    o.severity = Severity::S1;
    l.record(A, C, &o);
    assert!(l.plan(A, C).is_none());
    assert!(l.overdue(1000 * DAY).is_empty());
}
