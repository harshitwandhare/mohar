//! The trust rules from docs/design.md section 4, checked exactly: promotion, proportionate demotion
//! by class, remediation, suspension, the ceiling, and the cases that always reach a person.
#![allow(clippy::expect_used)]

use mohar_core::policy::{Capability, Risk};
use mohar_core::trust::{
    ASK_FIRST, HumanReview, Ledger, MIN_REVIEW_SECS, Outcome, REMEDIATION_PASSES, SUPERVISED,
    Severity, TRUSTED, review_per_mille, sampled_for_review, wilson_lower,
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
        verifier: "tests".into(),
    }
}

fn fail(at: u64, severity: Severity) -> Outcome {
    Outcome {
        at,
        passed: false,
        severity,
        exercises_failure: false,
        related: vec![],
        verifier: "tests".into(),
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
            l.record(A, "fs.edit.docs", &Outcome { at: t, passed, severity, exercises_failure: true, related: vec![], verifier: "tests".into() });
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

#[test]
fn a_high_risk_irreversible_capability_stops_at_supervised_whatever_its_ceiling() {
    let drop_table = cap(Risk::High, false, 2);
    let mut l = Ledger::new();
    passes(&mut l, "db.migrate.prod", 500, 0);
    for day in [7, 14, 30, 90] {
        assert_eq!(
            l.level(A, "db.migrate.prod", &drop_table, day * DAY),
            SUPERVISED,
            "day {day}"
        );
    }
    // The same record on a reversible high-risk capability does reach Trusted.
    let deploy = cap(Risk::High, true, 2);
    passes(&mut l, "deploy.staging", 500, 0);
    assert_eq!(l.level(A, "deploy.staging", &deploy, 7 * DAY), SUPERVISED);
    assert_eq!(l.level(A, "deploy.staging", &deploy, 14 * DAY), TRUSTED);
}

#[test]
fn a_suspended_agent_is_at_ask_first_everywhere() {
    let docs = cap(Risk::Low, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.docs", 40, 0);
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 7 * DAY), SUPERVISED);
    l.record(A, "fs.edit.other", &fail(7 * DAY, Severity::S4));
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 30 * DAY), ASK_FIRST);
    l.reinstate(A);
    assert_eq!(l.level(A, "fs.edit.docs", &docs, 30 * DAY), SUPERVISED);
}

#[test]
fn a_trusted_agent_runs_medium_risk_actions_without_asking() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 200, 0);
    assert_eq!(
        l.decide(A, "fs.edit.code", &code, 7 * DAY).result,
        "escalate"
    );
    let v = l.decide(A, "fs.edit.code", &code, 14 * DAY);
    assert_eq!((v.result, v.level), ("allow", TRUSTED));
}

#[test]
fn the_default_failure_class_follows_risk_and_reversibility() {
    assert_eq!(
        Severity::for_capability(&cap(Risk::High, true, 2)),
        Severity::S3
    );
    assert_eq!(
        Severity::for_capability(&cap(Risk::Low, false, 2)),
        Severity::S3
    );
    assert_eq!(
        Severity::for_capability(&cap(Risk::Medium, true, 2)),
        Severity::S2
    );
    assert_eq!(
        Severity::for_capability(&cap(Risk::Low, true, 2)),
        Severity::S1
    );
    assert_eq!(
        Severity::for_capability(&cap(Risk::None, true, 2)),
        Severity::S1
    );
}

/// A person's review of an action: who reviewed it and how long they spent.
fn review(reviewer: &str, seconds: u64) -> HumanReview {
    HumanReview {
        reviewer: reviewer.to_string(),
        seconds,
    }
}

#[test]
fn a_quick_human_accept_does_not_count_toward_promotion() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    let quick = review("person:r1", MIN_REVIEW_SECS - 1);
    for _ in 0..20 {
        assert!(!l.record_human(A, "fs.edit.code", &pass(0), &quick));
    }
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), ASK_FIRST);
    let careful = review("person:r2", MIN_REVIEW_SECS);
    for _ in 0..20 {
        assert!(l.record_human(A, "fs.edit.code", &pass(0), &careful));
    }
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
}

#[test]
fn a_human_reject_always_counts_however_quick() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    passes(&mut l, "fs.edit.code", 20, 0);
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
    let quick = review("person:r1", 0);
    assert!(l.record_human(A, "fs.edit.code", &fail(7 * DAY, Severity::S2), &quick));
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), ASK_FIRST);
}

/// `approved` accepts and then `rejected` rejects from one reviewer, each read for long enough.
fn history(l: &mut Ledger, reviewer: &str, approved: u32, rejected: u32) {
    let r = review(reviewer, MIN_REVIEW_SECS);
    for _ in 0..approved {
        l.record_human("agent:test/other", "fs.edit.docs", &pass(0), &r);
    }
    for _ in 0..rejected {
        l.record_human(
            "agent:test/other",
            "fs.edit.docs",
            &fail(0, Severity::S1),
            &r,
        );
    }
}

#[test]
fn a_reviewer_approving_more_than_95_percent_of_the_last_50_stops_counting() {
    let r = review("person:r1", MIN_REVIEW_SECS);
    // 47 of 50 is 94%: still counts.
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 47, 3);
    assert!(!l.is_rubber_stamping("person:r1"));
    assert!(l.record_human(A, "fs.edit.code", &pass(0), &r));
    // 48 of the last 50 is 96%: the next accept doesn't count.
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 48, 2);
    assert!(l.is_rubber_stamping("person:r1"));
    assert!(!l.record_human(A, "fs.edit.code", &pass(0), &r));
    // Fewer than 50 reviews say nothing yet, even if all were accepts.
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 49, 0);
    assert!(!l.is_rubber_stamping("person:r1"));
    // Other reviewers are unaffected.
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 50, 0);
    assert!(l.record_human(
        A,
        "fs.edit.code",
        &pass(0),
        &review("person:r2", MIN_REVIEW_SECS)
    ));
}

#[test]
fn only_the_last_50_reviews_set_the_rate() {
    let mut l = Ledger::new();
    // 10 rejects long ago, then 50 accepts: the last 50 are all accepts.
    history(&mut l, "person:r1", 0, 10);
    history(&mut l, "person:r1", 50, 0);
    assert!(l.is_rubber_stamping("person:r1"));
}

#[test]
fn rubber_stamping_lasts_until_a_sampled_recheck_passes() {
    let r = review("person:r1", MIN_REVIEW_SECS);
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 50, 0);
    // Rejecting a few more doesn't lift it; only a re-check does.
    history(&mut l, "person:r1", 0, 5);
    assert!(l.is_rubber_stamping("person:r1"));
    l.recheck("person:r1", false);
    assert!(
        l.is_rubber_stamping("person:r1"),
        "a failed re-check keeps it"
    );
    l.recheck("person:r1", true);
    assert!(!l.is_rubber_stamping("person:r1"));
    assert!(l.record_human(A, "fs.edit.code", &pass(0), &r));
    // The re-check starts a fresh window: one more accept doesn't flag them again.
    assert!(!l.is_rubber_stamping("person:r1"));
}

#[test]
fn tests_and_diffs_are_unaffected_by_reviewer_flags() {
    let code = cap(Risk::Medium, true, 2);
    let mut l = Ledger::new();
    history(&mut l, "person:r1", 50, 0);
    passes(&mut l, "fs.edit.code", 20, 0);
    assert_eq!(l.level(A, "fs.edit.code", &code, 7 * DAY), SUPERVISED);
}

/// How many of `n` receipts from `start` are sampled at `level` under `seed`.
fn sampled(seed: &[u8; 32], level: u8, start: u64, n: u64) -> u64 {
    (start..start + n)
        .filter(|&seq| sampled_for_review(seed, seq, level))
        .count() as u64
}

#[test]
fn review_sampling_runs_at_twenty_and_five_percent_and_never_at_ask_first() {
    assert_eq!(
        (
            review_per_mille(ASK_FIRST),
            review_per_mille(SUPERVISED),
            review_per_mille(TRUSTED)
        ),
        (0, 200, 50)
    );
    // 20,000 draws per seed: the binomial standard deviation is about 57 at 20% and 31 at 5%, so the
    // bounds below are more than six of them wide and a correct sampler never misses them.
    let n = 20_000;
    for k in 0u8..4 {
        let seed = [k.wrapping_mul(37).wrapping_add(1); 32];
        let s = sampled(&seed, SUPERVISED, 0, n);
        assert!(
            (3_650..=4_350).contains(&s),
            "Supervised, seed {k}: {s} of {n}"
        );
        let t = sampled(&seed, TRUSTED, 0, n);
        assert!((810..=1_190).contains(&t), "Trusted, seed {k}: {t} of {n}");
        assert_eq!(sampled(&seed, ASK_FIRST, 0, n), 0);
        assert_eq!(sampled(&seed, 7, 0, n), 0, "no level above Trusted samples");
    }
}

#[test]
fn review_sampling_is_reproducible_from_the_seed_and_differs_between_seeds() {
    let (a, b) = ([1u8; 32], [2u8; 32]);
    let draw = |seed: &[u8; 32]| -> Vec<bool> {
        (0..2_000)
            .map(|seq| sampled_for_review(seed, seq, SUPERVISED))
            .collect()
    };
    assert_eq!(draw(&a), draw(&a), "same seed, same sample");
    let differ = draw(&a)
        .iter()
        .zip(draw(&b))
        .filter(|(x, y)| **x != *y)
        .count();
    // Two independent 20% samples disagree on 32% of draws; anything near zero means the seed is
    // ignored.
    assert!(differ > 400, "{differ} of 2000 differ");
}

#[test]
fn successive_receipts_are_sampled_independently() {
    // A sampler that picked runs of receipts would let an agent learn the pattern. Count how often a
    // sampled receipt is followed by another: for independent draws that is about 20%.
    let seed = [9u8; 32];
    let draws: Vec<bool> = (0..20_000)
        .map(|seq| sampled_for_review(&seed, seq, SUPERVISED))
        .collect();
    let after_hit: Vec<bool> = draws.windows(2).filter(|w| w[0]).map(|w| w[1]).collect();
    let rate = after_hit.iter().filter(|&&x| x).count() as f64 / after_hit.len() as f64;
    assert!((0.16..=0.24).contains(&rate), "{rate}");
}
