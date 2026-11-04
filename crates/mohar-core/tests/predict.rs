//! The per-person answer model and the rule for when it may answer for the person (docs/design.md
//! section 6, "Learning a person's answers").
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use mohar_core::policy::{Capability, Risk};
use mohar_core::predict::{
    CHECK_PER_MILLE, Limits, MIN_ANSWERS, Model, Past, Prediction, Request, THRESHOLD, Why, decide,
};
use proptest::prelude::*;

const SEED: [u8; 32] = [7; 32];
const DOCS: &str = "fs.edit.docs";
const CONFIG: &str = "fs.edit.config";

fn low() -> Capability {
    Capability {
        risk: Risk::Low,
        reversible: true,
        ceiling: 2,
    }
}

fn past(capability: &str, risk: Risk, target: &str, yes: bool) -> Past {
    Past {
        capability: capability.into(),
        risk,
        target: target.into(),
        yes,
    }
}

fn enabled(capability: &str, paths: &[&str], per_day: u32) -> BTreeMap<String, Limits> {
    BTreeMap::from([(
        capability.to_string(),
        Limits {
            paths: paths.iter().map(|p| p.to_string()).collect(),
            per_day,
        },
    )])
}

fn request<'a>(spec: &'a Capability, target: &'a str, p_yes: Option<f64>) -> Request<'a> {
    Request {
        capability: DOCS,
        spec,
        target,
        used_today: 0,
        p_yes,
    }
}

/// The first sequence number at or after `from` that is not drawn for a check.
fn unchecked(from: u64) -> u64 {
    let spec = low();
    let limits = enabled(DOCS, &["**"], 100);
    (from..)
        .find(|&seq| {
            !matches!(
                decide(&request(&spec, "docs/a.md", Some(1.0)), &limits, &SEED, seq),
                Prediction::Check { .. }
            )
        })
        .expect("some sequence number is not checked")
}

#[test]
fn a_confident_model_answers_yes_on_an_enabled_low_risk_reversible_capability() {
    let spec = low();
    let seq = unchecked(0);
    let got = decide(
        &request(&spec, "docs/guide.md", Some(0.99)),
        &enabled(DOCS, &["docs/**"], 10),
        &SEED,
        seq,
    );
    assert_eq!(got, Prediction::Yes { p_yes: 0.99 });
}

#[test]
fn medium_and_high_risk_or_irreversible_capabilities_are_never_predicted() {
    let limits = enabled(DOCS, &["**"], 1000);
    for (risk, reversible) in [
        (Risk::Medium, true),
        (Risk::High, true),
        (Risk::None, false),
        (Risk::Low, false),
        (Risk::High, false),
    ] {
        let spec = Capability {
            risk,
            reversible,
            ceiling: 2,
        };
        for seq in 0..200 {
            assert_eq!(
                decide(&request(&spec, "docs/a.md", Some(1.0)), &limits, &SEED, seq),
                Prediction::Ask(Why::Risky),
                "{risk:?} reversible={reversible} seq={seq}"
            );
        }
    }
}

#[test]
fn a_capability_with_no_risk_is_low_enough() {
    let spec = Capability {
        risk: Risk::None,
        reversible: true,
        ceiling: 2,
    };
    let seq = unchecked(0);
    assert_eq!(
        decide(
            &request(&spec, "docs/a.md", Some(0.99)),
            &enabled(DOCS, &["**"], 1),
            &SEED,
            seq
        ),
        Prediction::Yes { p_yes: 0.99 }
    );
}

#[test]
fn nothing_is_predicted_unless_the_person_switched_it_on_for_that_capability() {
    let spec = low();
    let got = decide(
        &request(&spec, "docs/a.md", Some(1.0)),
        &enabled(CONFIG, &["**"], 10),
        &SEED,
        unchecked(0),
    );
    assert_eq!(got, Prediction::Ask(Why::NotEnabled));
    let got = decide(
        &request(&spec, "docs/a.md", Some(1.0)),
        &BTreeMap::new(),
        &SEED,
        unchecked(0),
    );
    assert_eq!(got, Prediction::Ask(Why::NotEnabled));
}

#[test]
fn the_target_must_be_inside_the_paths_the_person_set() {
    let spec = low();
    let seq = unchecked(0);
    let limits = enabled(DOCS, &["docs/**", "README.md"], 10);
    for target in ["src/lib.rs", "docs", "../docs/a.md", "README.md.bak", ""] {
        assert_eq!(
            decide(&request(&spec, target, Some(1.0)), &limits, &SEED, seq),
            Prediction::Ask(Why::OutsideLimits),
            "{target}"
        );
    }
    for target in ["docs/a.md", "docs/deep/b.md", "README.md"] {
        assert!(
            matches!(
                decide(&request(&spec, target, Some(1.0)), &limits, &SEED, seq),
                Prediction::Yes { .. }
            ),
            "{target}"
        );
    }
}

#[test]
fn limits_with_no_paths_allow_nothing() {
    let spec = low();
    let got = decide(
        &request(&spec, "docs/a.md", Some(1.0)),
        &enabled(DOCS, &[], 10),
        &SEED,
        unchecked(0),
    );
    assert_eq!(got, Prediction::Ask(Why::OutsideLimits));
}

#[test]
fn the_daily_limit_stops_prediction_once_reached() {
    let spec = low();
    let limits = enabled(DOCS, &["**"], 3);
    let seq = unchecked(0);
    for used in 0..3 {
        let mut r = request(&spec, "docs/a.md", Some(1.0));
        r.used_today = used;
        assert!(matches!(
            decide(&r, &limits, &SEED, seq),
            Prediction::Yes { .. }
        ));
    }
    for used in [3, 4, u32::MAX] {
        let mut r = request(&spec, "docs/a.md", Some(1.0));
        r.used_today = used;
        assert_eq!(
            decide(&r, &limits, &SEED, seq),
            Prediction::Ask(Why::DailyLimit)
        );
    }
    assert_eq!(
        decide(
            &request(&spec, "docs/a.md", Some(1.0)),
            &enabled(DOCS, &["**"], 0),
            &SEED,
            seq
        ),
        Prediction::Ask(Why::DailyLimit)
    );
}

#[test]
fn below_the_threshold_or_without_a_model_the_person_is_asked() {
    let spec = low();
    let limits = enabled(DOCS, &["**"], 10);
    let seq = unchecked(0);
    let just_under = THRESHOLD - 1e-9;
    for p in [just_under, 0.5, 0.0, f64::NAN, -1.0, f64::NEG_INFINITY] {
        assert_eq!(
            decide(&request(&spec, "docs/a.md", Some(p)), &limits, &SEED, seq),
            Prediction::Ask(Why::Unsure),
            "{p}"
        );
    }
    assert_eq!(
        decide(&request(&spec, "docs/a.md", None), &limits, &SEED, seq),
        Prediction::Ask(Why::NoModel)
    );
    assert!(matches!(
        decide(
            &request(&spec, "docs/a.md", Some(THRESHOLD)),
            &limits,
            &SEED,
            seq
        ),
        Prediction::Yes { .. }
    ));
}

#[test]
fn about_one_in_twenty_predictions_still_goes_to_the_person() {
    let spec = low();
    let limits = enabled(DOCS, &["**"], 10);
    let n = 20_000u64;
    let checked = (0..n)
        .filter(|&seq| {
            match decide(
                &request(&spec, "docs/a.md", Some(0.99)),
                &limits,
                &SEED,
                seq,
            ) {
                Prediction::Check { p_yes } => {
                    assert_eq!(p_yes, 0.99);
                    true
                }
                Prediction::Yes { .. } => false,
                other => panic!("{other:?}"),
            }
        })
        .count() as u64;
    assert_eq!(CHECK_PER_MILLE, 50);
    // 5% of 20,000 is 1,000; a fair draw lands within 150 of it far more often than 1 in 10^6.
    assert!((850..=1150).contains(&checked), "{checked}");
    // The draw depends on the seed, so the agent can't tell which actions will be checked.
    let other: Vec<u64> = (0..200)
        .filter(|&seq| {
            matches!(
                decide(
                    &request(&spec, "docs/a.md", Some(0.99)),
                    &limits,
                    &[8; 32],
                    seq
                ),
                Prediction::Check { .. }
            )
        })
        .collect();
    let mine: Vec<u64> = (0..200)
        .filter(|&seq| {
            matches!(
                decide(
                    &request(&spec, "docs/a.md", Some(0.99)),
                    &limits,
                    &SEED,
                    seq
                ),
                Prediction::Check { .. }
            )
        })
        .collect();
    assert_ne!(mine, other);
}

#[test]
fn checks_are_drawn_apart_from_review_samples() {
    // The same seed and sequence number feed review sampling; a separate tag keeps the two draws
    // independent, so a check isn't always a reviewed action too.
    let spec = low();
    let limits = enabled(DOCS, &["**"], 10);
    let both = (0..20_000u64)
        .filter(|&seq| {
            matches!(
                decide(
                    &request(&spec, "docs/a.md", Some(0.99)),
                    &limits,
                    &SEED,
                    seq
                ),
                Prediction::Check { .. }
            ) && mohar_core::trust::sampled_at(&SEED, seq, 200)
        })
        .count();
    // Independent draws at 5% and 20% overlap on about 1% (200 of 20,000).
    assert!((120..=280).contains(&both), "{both}");
}

#[test]
fn too_few_answers_means_no_model() {
    let few: Vec<Past> = (0..MIN_ANSWERS - 1)
        .map(|i| past(DOCS, Risk::Low, &format!("docs/{i}.md"), true))
        .collect();
    assert!(Model::train(&few).is_none());
    assert!(Model::train(&[]).is_none());
}

#[test]
fn a_short_run_of_yeses_is_not_enough_to_answer() {
    // Platt's smoothed targets cap the probability near (yes + 1) / (yes + 2), so a person has to have
    // said yes about 50 times before the model can reach 0.98.
    let answers: Vec<Past> = (0..40)
        .map(|i| past(DOCS, Risk::Low, &format!("docs/{i}.md"), true))
        .collect();
    let m = Model::train(&answers).expect("40 answers is enough to train");
    let p = m.p_yes(&answers, DOCS, Risk::Low, "docs/new.md");
    assert!(p < THRESHOLD, "{p}");
    assert!(p > 0.9, "{p}");
}

#[test]
fn the_model_learns_which_capabilities_a_person_approves() {
    let mut answers = Vec::new();
    for i in 0..150 {
        answers.push(past(DOCS, Risk::Low, &format!("docs/{i}.md"), true));
        answers.push(past(CONFIG, Risk::Low, &format!("config/{i}.toml"), false));
    }
    let m = Model::train(&answers).expect("enough answers");
    let docs = m.p_yes(&answers, DOCS, Risk::Low, "docs/next.md");
    let config = m.p_yes(&answers, CONFIG, Risk::Low, "config/next.toml");
    assert!(docs >= THRESHOLD, "{docs}");
    assert!(config < 0.1, "{config}");
}

#[test]
fn the_model_learns_paths_within_a_capability() {
    let mut answers = Vec::new();
    for i in 0..150 {
        answers.push(past(DOCS, Risk::Low, &format!("docs/{i}.md"), true));
        answers.push(past(DOCS, Risk::Low, &format!("legal/{i}.md"), false));
    }
    let m = Model::train(&answers).expect("enough answers");
    let docs = m.p_yes(&answers, DOCS, Risk::Low, "docs/next.md");
    let legal = m.p_yes(&answers, DOCS, Risk::Low, "legal/next.md");
    assert!(docs > legal + 0.5, "docs {docs} legal {legal}");
}

#[test]
fn a_person_who_says_yes_nine_times_in_ten_is_not_predicted() {
    // Calibration: the probability tracks how often the person actually says yes, so a 90% approver
    // stays near 0.9 and well under the threshold however many answers there are.
    let answers: Vec<Past> = (0..500)
        .map(|i| past(DOCS, Risk::Low, &format!("docs/{i}.md"), i % 10 != 3))
        .collect();
    let m = Model::train(&answers).expect("enough answers");
    let p = m.p_yes(&answers, DOCS, Risk::Low, "docs/next.md");
    assert!((0.8..0.95).contains(&p), "{p}");
}

#[test]
fn a_recent_run_of_noes_pulls_the_probability_down() {
    // A person whose noes come in streaks (30 yes, then 8 no, over and over, ending on a run of yeses): after a few noes, the
    // next answer is likely no too, and the model should learn that from the recent history.
    let mut answers: Vec<Past> = (0..220)
        .map(|i| past(DOCS, Risk::Low, &format!("docs/{i}.md"), i % 38 < 30))
        .collect();
    let m = Model::train(&answers).expect("enough answers");
    let before = m.p_yes(&answers, DOCS, Risk::Low, "docs/next.md");
    answers.extend((0..6).map(|i| past(DOCS, Risk::Low, &format!("docs/no{i}.md"), false)));
    let after = m.p_yes(&answers, DOCS, Risk::Low, "docs/next.md");
    assert!(after < before - 0.1, "before {before} after {after}");
}

#[test]
fn training_is_deterministic() {
    let answers: Vec<Past> = (0..120)
        .map(|i| past(DOCS, Risk::Low, &format!("docs/{i}.md"), i % 7 != 0))
        .collect();
    assert_eq!(Model::train(&answers), Model::train(&answers));
}

proptest! {
    #[test]
    fn nothing_but_low_risk_reversible_is_ever_predicted(
        risk in prop_oneof![Just(Risk::None), Just(Risk::Low), Just(Risk::Medium), Just(Risk::High)],
        reversible in any::<bool>(),
        p in prop::num::f64::ANY,
        used in any::<u32>(),
        per_day in any::<u32>(),
        seq in any::<u64>(),
        target in "[a-z./]{0,12}",
    ) {
        let spec = Capability { risk, reversible, ceiling: 2 };
        let r = Request { capability: DOCS, spec: &spec, target: &target, used_today: used, p_yes: Some(p) };
        let got = decide(&r, &enabled(DOCS, &["**"], per_day), &SEED, seq);
        if risk > Risk::Low || !reversible {
            prop_assert_eq!(got, Prediction::Ask(Why::Risky));
        }
        if let Prediction::Yes { p_yes } | Prediction::Check { p_yes } = got {
            prop_assert!(p_yes >= THRESHOLD);
            prop_assert!(used < per_day);
        }
    }

    #[test]
    fn probabilities_stay_between_zero_and_one(
        labels in prop::collection::vec(any::<bool>(), 30..120),
        dirs in prop::collection::vec("[a-z]{1,3}", 1..4),
    ) {
        let answers: Vec<Past> = labels.iter().enumerate().map(|(i, &yes)| {
            let dir = &dirs[i % dirs.len()];
            past(DOCS, Risk::Low, &format!("{dir}/{i}.md"), yes)
        }).collect();
        let m = Model::train(&answers).expect("at least MIN_ANSWERS");
        for dir in &dirs {
            let p = m.p_yes(&answers, DOCS, Risk::Low, &format!("{dir}/x.md"));
            prop_assert!(p.is_finite() && (0.0..=1.0).contains(&p), "{}", p);
        }
    }
}
