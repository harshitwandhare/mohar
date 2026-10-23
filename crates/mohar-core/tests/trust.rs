//! The trust rules from docs/design.md section 4, checked exactly: promotion, proportionate demotion
//! by class, remediation, suspension, the ceiling, and the cases that always reach a person.
#![allow(clippy::expect_used)]

use mohar_core::policy::{Capability, Risk};
use mohar_core::trust::{
    ASK_FIRST, Ledger, Outcome, REMEDIATION_PASSES, SUPERVISED, Severity, TRUSTED, wilson_lower,
};
use proptest::prelude::*;

const DAY: u64 = 86_400;
const A: &str = "agent:test/1";

fn cap(risk: Risk, reversible: bool, ceiling: u8) -> Capability {
    Capability {
        risk,
        reversible,
        ceiling,
    }
}

fn pass(at: u64) -> Outcome {
    Outcome {
        at,
        passed: true,
        severity: Severity::S1,
        exercises_failure: false,
        related: vec![],
    }
}

fn fail(at: u64, severity: Severity) -> Outcome {
    Outcome {
        at,
        passed: false,
        severity,
        exercises_failure: false,
        related: vec![],
    }
}

/// `n` verified passes on `capability`, all at time `at`.
fn passes(l: &mut Ledger, capability: &str, n: u32, at: u64) {
    for _ in 0..n {
        l.record(A, capability, &pass(at));
    }
}

#[test]
fn the_wilson_bound_matches_the_design_example() {
    // "5 successes out of 5 give a lower bound of about 0.57."
    assert!((wilson_lower(5.0, 0.0) - 0.566).abs() < 0.01);
    assert_eq!(wilson_lower(0.0, 0.0), 0.0);
}

#[test]
fn promotion_needs_evidence_and_seven_days_at_the_level() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 20, 0);
    assert_eq!(
        l.level(A, "fs.edit.code", &code, 6 * DAY),
        ASK_FIRST,
        "not yet 7 days"
    );
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
    // Trusted needs 30 weighted outcomes and a bound of 0.95, and 7 more days at Supervised.
    passes(&mut l, "fs.edit.code", 100, 7 * DAY);
    assert_eq!(l.level(A, "fs.edit.code", &code, 13 * DAY), SUPERVISED);
    assert_eq!(l.level(A, "fs.edit.code", &code, 14 * DAY), TRUSTED);
}

#[test]
fn evidence_fades_with_a_thirty_day_half_life() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 20, 0);
    // 120 days later, 20 passes weigh 20/16 = 1.25: far short of 10.
    assert_eq!(l.level(A, "fs.edit.code", &code, 120 * DAY), ASK_FIRST);
}

#[test]
fn a_minor_failure_changes_no_level_and_three_in_fourteen_days_count_as_one_level() {
    let docs = cap(Risk::Low, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 40, 0);
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 7 * DAY), SUPERVISED);
    l.record(A, "fs.edit.docs", &fail(8 * DAY, Severity::S1));
    l.record(A, "fs.edit.docs", &fail(9 * DAY, Severity::S1));
    assert_eq!(
        l.level(A, "fs.edit.docs", &docs, 9 * DAY),
        SUPERVISED,
        "S1 alone changes nothing"
    );
    assert!(!l.in_remediation(A, "fs.edit.docs"));
    l.record(A, "fs.edit.docs", &fail(10 * DAY, Severity::S1));
    assert_eq!(
        l.level(A, "fs.edit.docs", &docs, 10 * DAY),
        ASK_FIRST,
        "the third within 14 days"
    );
    assert!(l.in_remediation(A, "fs.edit.docs"));
}

#[test]
fn minor_failures_spread_out_are_only_evidence() {
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 40, 0);
    for d in [8, 23, 38] {
        l.record(A, "fs.edit.docs", &fail(d * DAY, Severity::S1));
    }
    assert!(!l.in_remediation(A, "fs.edit.docs"));
}

#[test]
fn a_near_miss_changes_nothing() {
    let docs = cap(Risk::Low, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 40, 0);
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 7 * DAY), SUPERVISED);
    l.record(A, "fs.edit.docs", &fail(8 * DAY, Severity::S0));
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 8 * DAY), SUPERVISED);
    assert!(!l.in_remediation(A, "fs.edit.docs"));
}

#[test]
fn a_meaningful_failure_drops_one_level_and_remediation_brings_it_back() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 20, 0);
    passes(&mut l, "fs.edit.code", 100, 7 * DAY);
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
    assert_eq!(l.level(A, "fs.edit.code", &code, 14 * DAY), TRUSTED);
    l.record(A, "fs.edit.code", &fail(15 * DAY, Severity::S2));
    assert_eq!(
        l.level(A, "fs.edit.code", &code, 15 * DAY),
        SUPERVISED,
        "down one, not to zero"
    );
    // Five passes, none exercising the failure: still in remediation until one does.
    for i in 0..REMEDIATION_PASSES {
        l.record(A, "fs.edit.code", &pass(16 * DAY + u64::from(i)));
    }
    assert!(l.in_remediation(A, "fs.edit.code"));
    let mut exercise = pass(17 * DAY);
    exercise.exercises_failure = true;
    l.record(A, "fs.edit.code", &exercise);
    assert!(!l.in_remediation(A, "fs.edit.code"));
    // Back on the normal path, but the failure stays in the evidence: the old record alone no longer
    // clears the bound for Trusted, so it takes fresh verified work as well as 7 days at the level.
    assert_eq!(l.level(A, "fs.edit.code", &code, 22 * DAY), SUPERVISED);
    passes(&mut l, "fs.edit.code", 150, 18 * DAY);
    assert_eq!(
        l.level(A, "fs.edit.code", &code, 21 * DAY),
        SUPERVISED,
        "7 days at the level first"
    );
    assert_eq!(l.level(A, "fs.edit.code", &code, 22 * DAY), TRUSTED);
}

#[test]
fn remediation_blocks_promotion() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 40, 0);
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
    l.record(A, "fs.edit.code", &fail(8 * DAY, Severity::S2));
    passes(&mut l, "fs.edit.code", 100, 8 * DAY);
    // Plenty of passes, none exercising the failure: the plan isn't finished, so no promotion even
    // weeks later, however strong the evidence.
    assert!(l.in_remediation(A, "fs.edit.code"));
    assert_eq!(l.level(A, "fs.edit.code", &code, 30 * DAY), ASK_FIRST);
}

#[test]
fn a_serious_failure_drops_the_capability_and_its_scope_to_ask_first_and_nothing_else() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    for c in ["db.migrate.staging", "db.seed", "fs.edit.docs"] {
        passes(&mut l, c, 40, 0);
        assert_eq!(l.level(A, c, &code, 7 * DAY), SUPERVISED);
    }
    let mut o = fail(8 * DAY, Severity::S3);
    o.related = vec!["db.seed".into()];
    l.record(A, "db.migrate.staging", &o);
    assert_eq!(l.level(A, "db.migrate.staging", &code, 8 * DAY), ASK_FIRST);
    assert_eq!(
        l.level(A, "db.seed", &code, 8 * DAY),
        ASK_FIRST,
        "shares its scope"
    );
    assert_eq!(
        l.level(A, "fs.edit.docs", &code, 8 * DAY),
        SUPERVISED,
        "unrelated, untouched"
    );
    assert!(!l.is_suspended(A));
}

#[test]
fn after_a_serious_failure_no_promotion_for_fourteen_days() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    l.record(A, "fs.edit.code", &fail(0, Severity::S3));
    let mut exercise = pass(DAY);
    exercise.exercises_failure = true;
    for _ in 0..REMEDIATION_PASSES {
        l.record(A, "fs.edit.code", &exercise);
    }
    passes(&mut l, "fs.edit.code", 60, DAY);
    assert!(!l.in_remediation(A, "fs.edit.code"));
    assert_eq!(l.level(A, "fs.edit.code", &code, 13 * DAY), ASK_FIRST);
    assert_eq!(l.level(A, "fs.edit.code", &code, 14 * DAY), SUPERVISED);
}

#[test]
fn an_integrity_failure_suspends_the_agent_everywhere_until_a_person_reinstates_it() {
    let docs = cap(Risk::Low, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 40, 0);
    l.record(A, "fs.edit.tests", &fail(8 * DAY, Severity::S4));
    assert!(l.is_suspended(A));
    assert_eq!(l.decide(A, "fs.edit.docs", &docs, 8 * DAY).result, "deny");
    let read = cap(Risk::None, true, 2);
    assert_eq!(
        l.decide(A, "fs.read", &read, 8 * DAY).result,
        "deny",
        "even reads"
    );
    assert_eq!(
        l.decide("agent:other/1", "fs.read", &read, 8 * DAY).result,
        "allow",
        "only that agent"
    );
    l.reinstate(A);
    assert!(!l.is_suspended(A));
}

#[test]
fn an_irreversible_high_impact_action_reaches_a_person_at_every_level() {
    let push_main = cap(Risk::High, false, 1);
    let mut l = Ledger::new();
    passes(&mut l, "git.push.main", 200, 0);
    for day in [0, 7, 14, 60] {
        let v = l.decide(A, "git.push.main", &push_main, day * DAY);
        assert_eq!(v.result, "escalate", "day {day}, level {}", v.level);
    }
}

#[test]
fn decisions_follow_the_level_and_the_capability() {
    let docs = cap(Risk::Low, true, 2);
    let code = cap(Risk::Medium, true, 2);
    let read = cap(Risk::None, true, 2);
    let mut l = Ledger::new();
    assert_eq!(
        l.decide(A, "fs.read", &read, 0).result,
        "allow",
        "no effect, no question"
    );
    assert_eq!(
        l.decide(A, "fs.edit.docs", &docs, 0).result,
        "escalate",
        "Ask first"
    );
    passes(&mut l, "fs.edit.docs", 40, 0);
    passes(&mut l, "fs.edit.code", 40, 0);
    assert_eq!(
        l.decide(A, "fs.edit.docs", &docs, 7 * DAY).result,
        "allow",
        "Supervised, low risk"
    );
    assert_eq!(
        l.decide(A, "fs.edit.code", &code, 7 * DAY).result,
        "escalate",
        "Supervised, medium risk"
    );
}

proptest! {
    /// A short streak never promotes: fewer than 10 verified passes, whenever and however spread.
    #[test]
    fn a_lucky_short_streak_never_promotes(n in 0u32..10, spread in 0u64..30, at in 0u64..400) {
        let docs = cap(Risk::Low, true, 2);
        let mut l = Ledger::new();
        for i in 0..n {
            l.record(A, "fs.edit.docs", &pass(u64::from(i) * spread * 3_600));
        }
        prop_assert_eq!(l.level(A, "fs.edit.docs", &docs, at * DAY), ASK_FIRST);
    }

    /// Whatever happens, no level exceeds the capability's ceiling, and a serious failure always
    /// leaves the capability at Ask first.
    #[test]
    fn the_ceiling_holds_and_serious_failures_always_reach_ask_first(
        ceiling in 0u8..=2,
        events in proptest::collection::vec((0u64..60, prop::bool::ANY, 0u8..5), 0..200),
    ) {
        let spec = cap(Risk::Low, true, ceiling);
        let mut l = Ledger::new();
        let mut t = 0;
        for (gap, passed, sev) in events {
            t += gap * 3_600;
            let severity = [Severity::S0, Severity::S1, Severity::S2, Severity::S3, Severity::S4][usize::from(sev)];
            l.record(A, "fs.edit.docs", &Outcome { at: t, passed, severity, exercises_failure: true, related: vec![] });
            if l.is_suspended(A) {
                l.reinstate(A);
            }
            let level = l.level(A, "fs.edit.docs", &spec, t);
            prop_assert!(level <= ceiling);
            if !passed && severity >= Severity::S3 {
                prop_assert_eq!(level, ASK_FIRST);
            }
        }
    }
}

#[test]
fn enough_outcomes_without_a_strong_enough_record_do_not_promote() {
    // 12 clean passes clear the minimum of 10, but their Wilson lower bound is about 0.76, under 0.80.
    let docs = cap(Risk::Low, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 12, 7 * DAY);
    assert!(wilson_lower(12.0, 0.0) < 0.80);
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 14 * DAY), ASK_FIRST);
}

#[test]
fn a_serious_failure_from_trusted_drops_all_the_way_not_one_level() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 20, 0);
    passes(&mut l, "fs.edit.code", 100, 7 * DAY);
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
    assert_eq!(l.level(A, "fs.edit.code", &code, 14 * DAY), TRUSTED);
    l.record(A, "fs.edit.code", &fail(15 * DAY, Severity::S3));
    assert_eq!(l.level(A, "fs.edit.code", &code, 15 * DAY), ASK_FIRST);
}
