//! Checks on the benchmark harness: that it is repeatable, that every policy sees the same tasks, and
//! that each metric counts what it says on agents whose behaviour is known exactly.

use mohar_bench::{
    Agreement, Config, Kind, Poisoning, Policy, agreement, false_promotion, interval, lessons,
    level_bound, markdown, report, run,
};

fn small(kinds: Vec<Kind>, catch: u64) -> Config {
    Config {
        seeds: vec![7],
        days: 35,
        actions_per_day: 6,
        kinds,
        agents_per_kind: 1,
        drift_day: 28,
        catch_per_mille: catch,
        escalations: 0,
        habits: Vec::new(),
        misleading: 0,
        plant_per_mille: 0,
        promote_per_mille: 0,
        spot_per_mille: 0,
    }
}

fn steady(name: &'static str, rate: u64) -> Kind {
    Kind {
        name,
        before: rate,
        after: rate,
    }
}

#[test]
fn a_run_is_repeatable() {
    let cfg = small(vec![steady("a", 900), steady("b", 600)], 500);
    assert_eq!(report(&cfg), report(&cfg));
}

#[test]
fn seeds_change_the_tasks() {
    let a = small(vec![steady("a", 600)], 0);
    let b = Config {
        seeds: vec![8],
        ..a.clone()
    };
    assert_ne!(
        run(&a, Policy::AlwaysAsk).incidents,
        run(&b, Policy::AlwaysAsk).incidents
    );
}

#[test]
fn every_policy_sees_the_same_tasks() {
    // Nobody stops anything, so every failing task becomes an incident whoever was asked.
    let cfg = small(vec![steady("a", 800), steady("b", 500)], 0);
    let tallies: Vec<_> = Policy::ALL.iter().map(|&p| run(&cfg, p)).collect();
    for t in &tallies {
        assert_eq!(t.actions, 2 * 35 * 6 * 3);
        assert_eq!(t.incidents, tallies[0].incidents);
    }
    assert_eq!(tallies[0].prompts, tallies[0].actions);
    // The allowlist runs the one low-risk reversible capability of three.
    assert_eq!(tallies[1].prompts, tallies[1].actions / 3 * 2);
}

#[test]
fn a_person_who_catches_everything_leaves_no_incidents_when_always_asked() {
    let cfg = small(vec![steady("a", 600)], 1000);
    let t = run(&cfg, Policy::AlwaysAsk);
    assert_eq!(t.incidents, 0);
    assert!(run(&cfg, Policy::Allowlist).incidents > 0);
}

#[test]
fn serious_incidents_are_the_irreversible_ones() {
    // Every action fails and nobody stops one, so exactly the third on deploy are serious.
    let cfg = small(vec![steady("a", 0)], 0);
    let t = run(&cfg, Policy::AlwaysAsk);
    assert_eq!(t.incidents, t.actions);
    assert_eq!(t.serious_incidents, t.actions / 3);
}

#[test]
fn demotion_follows_a_drop_by_the_rules_for_each_risk() {
    // Perfect for four weeks, then always failing, with nobody stopping anything: the medium and the
    // irreversible capability drop on the first failure, the low-risk one on the third minor failure.
    let cfg = small(
        vec![Kind {
            name: "drop",
            before: 1000,
            after: 0,
        }],
        0,
    );
    let t = run(&cfg, Policy::Mohar);
    let mut d = t.demotion_delays.clone();
    d.sort_unstable();
    assert_eq!(d, vec![1, 1, 3]);
    assert_eq!((t.drops_at_ask_first, t.never_demoted), (0, 0));
    assert_eq!(t.promotions[2], 2, "edit and deps reach Trusted");
    assert_eq!(t.false_promotions, [0, 0, 0]);
}

#[test]
fn a_drop_before_any_promotion_has_nothing_to_demote() {
    let cfg = Config {
        drift_day: 0,
        ..small(
            vec![Kind {
                name: "drop",
                before: 1000,
                after: 0,
            }],
            0,
        )
    };
    let t = run(&cfg, Policy::Mohar);
    assert_eq!(t.drops_at_ask_first, 3);
    assert!(t.demotion_delays.is_empty());
}

#[test]
fn a_drop_the_run_ends_on_is_never_demoted() {
    // The drop comes on the last day, with two actions on each capability, and every failure that is
    // asked about is stopped. Edit runs at Supervised and fails twice; deps and deploy are asked
    // about and refused as wrong twice. Two minor failures are not yet an S2, so none of the three
    // demotes before the run ends.
    let cfg = Config {
        days: 29,
        actions_per_day: 2,
        ..small(
            vec![Kind {
                name: "drop",
                before: 1000,
                after: 0,
            }],
            1000,
        )
    };
    let t = run(&cfg, Policy::Mohar);
    assert_eq!(t.never_demoted, 3);
}

#[test]
fn refusals_as_wrong_demote_a_drop_even_when_every_failure_is_stopped() {
    // Six actions a day: by the third refusal on a capability that is asked about, it is an S2.
    let cfg = Config {
        days: 29,
        ..small(
            vec![Kind {
                name: "drop",
                before: 1000,
                after: 0,
            }],
            1000,
        )
    };
    let t = run(&cfg, Policy::Mohar);
    assert_eq!(t.never_demoted, 0);
    assert_eq!(t.demotion_delays.len(), 3, "{:?}", t.demotion_delays);
}

#[test]
fn stopped_failures_are_refused_as_wrong_so_a_poor_agent_stays_at_ask_first() {
    // A 70% agent whose failures are all stopped at Ask first would show only passes if a refusal
    // recorded nothing, and would be promoted to Supervised, which stands for 80% (#222). Refused as
    // wrong, the failures stay on its record.
    let cfg = small(vec![steady("poor", 700)], 1000);
    for p in [Policy::Aggregate, Policy::Mohar] {
        let t = run(&cfg, p);
        assert_eq!(t.promotions, [0, 0, 0], "{}", p.name());
    }
}

/// False promotions as a share of all promotions.
fn false_rate(cfg: &Config) -> f64 {
    let t = run(cfg, Policy::Mohar);
    let all: u64 = t.promotions.iter().sum();
    t.false_promotions.iter().sum::<u64>() as f64 / all as f64
}

#[test]
fn a_careful_reviewer_no_longer_gets_poor_agents_promoted() {
    // The acceptance line of #222, on the published configuration: stopping half or nine in ten of
    // the failing actions a person is asked about raises the false promotion rate by at most one point.
    let at = |catch| {
        false_rate(&Config {
            catch_per_mille: catch,
            ..Config::default()
        })
    };
    let none = at(0);
    for catch in [500, 900] {
        let rate = at(catch);
        assert!(
            rate <= none + 0.01,
            "{catch} per 1000 stopped: {rate} against {none}"
        );
    }
}

#[test]
fn a_perfect_agent_is_never_falsely_promoted() {
    let cfg = small(vec![steady("good", 1000)], 500);
    for p in [Policy::Aggregate, Policy::Mohar] {
        let t = run(&cfg, p);
        assert!(t.promotions[1] > 0);
        assert_eq!(t.false_promotions, [0, 0, 0]);
    }
}

#[test]
fn false_promotion_is_judged_against_the_level() {
    assert_eq!(level_bound(0), 0);
    assert!(!false_promotion(0, 0));
    assert!(false_promotion(1, 799));
    assert!(!false_promotion(1, 800));
    assert!(false_promotion(2, 949));
    assert!(!false_promotion(2, 950));
}

#[test]
fn the_report_names_every_policy_and_compares_to_the_baselines() {
    let cfg = small(vec![steady("a", 900)], 500);
    let r = report(&cfg);
    let names: Vec<_> = r["policies"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| p["policy"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        names,
        ["always_ask", "static_allowlist", "aggregate_score", "mohar"]
    );
    assert_eq!(r["policies"][0]["prompts_avoided_vs_always_ask"], 0.0);
    assert_eq!(r["policies"][1]["incidents_at_or_below_allowlist"], true);
    assert!(r["policies"][0].get("promotions").is_none());
    assert!(r["policies"][3]["time_to_demotion"].is_object());
}

#[test]
fn an_empty_run_reports_zeros() {
    let cfg = Config {
        seeds: Vec::new(),
        ..small(vec![steady("a", 900)], 500)
    };
    let r = report(&cfg);
    assert_eq!(r["policies"][3]["prompts_per_1000"], 0.0);
    assert_eq!(r["policies"][3]["prompts_avoided_vs_always_ask"], 0.0);
    assert_eq!(r["policies"][3]["time_to_demotion"]["median_actions"], 0);
}

#[test]
fn results_file_matches_the_harness() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("results.json");
    let mut now = serde_json::to_string_pretty(&report(&Config::default())).unwrap_or_default();
    now.push('\n');
    if std::env::var_os("MOHAR_WRITE_BENCH").is_some() {
        std::fs::write(&path, &now).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == now,
        "results.json is out of date; run MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench"
    );
}

#[test]
fn the_write_up_quotes_the_harness() {
    // docs/benchmark.md carries the results tables between two markers; the prose around them is
    // written by hand. The tables must be what the harness produces now.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/benchmark.md");
    let doc = std::fs::read_to_string(&path).unwrap_or_default();
    let (start, end) = ("<!-- results:start -->\n", "<!-- results:end -->");
    let (Some(a), Some(b)) = (doc.find(start), doc.find(end)) else {
        panic!("{} has no results markers", path.display());
    };
    let now = format!(
        "{}{start}{}{}",
        &doc[..a],
        markdown(&report(&Config::default())),
        &doc[b..]
    );
    if std::env::var_os("MOHAR_WRITE_BENCH").is_some() {
        std::fs::write(&path, &now).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
    assert!(
        doc == now,
        "docs/benchmark.md is out of date; run MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench"
    );
}

#[test]
fn an_interval_needs_two_values() {
    assert_eq!(interval(&[]), None);
    assert_eq!(interval(&[3.0]), None);
}

#[test]
fn an_interval_is_the_student_t_interval_of_the_mean() {
    // Mean 12, sample standard deviation 2, n = 3: t(2) = 4.303, half width 4.303 * 2 / sqrt(3).
    let (mean, low, high) = interval(&[10.0, 12.0, 14.0]).unwrap_or_default();
    assert_eq!(mean, 12.0);
    assert!((low - 7.0313).abs() < 1e-3, "{low}");
    assert!((high - 16.9687).abs() < 1e-3, "{high}");
    // Eight seeds, as the published run: t(7) = 2.365.
    let xs = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    let (mean, low, high) = interval(&xs).unwrap_or_default();
    let sd = (42.0f64 / 7.0).sqrt();
    assert_eq!(mean, 4.5);
    assert!(
        (high - mean - 2.365 * sd / 8f64.sqrt()).abs() < 1e-3,
        "{high}"
    );
    assert!((mean - low - (high - mean)).abs() < 1e-9);
}

#[test]
fn an_interval_over_many_values_uses_the_normal_bound() {
    let xs: Vec<f64> = (0..100).map(|i| f64::from(i % 2)).collect();
    let (mean, low, high) = interval(&xs).unwrap_or_default();
    let sd = (25.0f64 / 99.0).sqrt();
    assert!((high - mean - 1.96 * sd / 10.0).abs() < 1e-9, "{high}");
    assert!(low > 0.0);
}

#[test]
fn identical_values_have_no_spread_and_a_rate_never_goes_below_zero() {
    assert_eq!(interval(&[5.0, 5.0, 5.0]), Some((5.0, 5.0, 5.0)));
    let (_, low, _) = interval(&[0.0, 0.0, 0.0, 9.0]).unwrap_or_default();
    assert_eq!(low, 0.0);
}

#[test]
fn the_report_gives_a_per_seed_interval_for_each_rate() {
    let cfg = Config {
        seeds: vec![1, 2, 3],
        ..small(vec![steady("a", 900), steady("b", 700)], 500)
    };
    let r = report(&cfg);
    for p in r["policies"].as_array().into_iter().flatten() {
        let s = &p["per_seed_95"];
        for key in [
            "prompts_per_1000",
            "incidents_per_1000",
            "prompts_avoided_vs_always_ask",
        ] {
            let (m, lo, hi) = (
                s[key]["mean"].as_f64(),
                s[key]["low"].as_f64(),
                s[key]["high"].as_f64(),
            );
            let (Some(m), Some(lo), Some(hi)) = (m, lo, hi) else {
                panic!("{} has no interval for {key}: {s}", p["policy"]);
            };
            assert!(lo <= m && m <= hi, "{key} {s}");
        }
        assert_eq!(
            s.get("false_promotion_rate").is_some(),
            p.get("promotions").is_some()
        );
    }
    // Always asking prompts on every action in every seed, so there is no spread.
    let ask = &r["policies"][0]["per_seed_95"]["prompts_per_1000"];
    assert_eq!(
        (ask["low"].as_f64(), ask["high"].as_f64()),
        (Some(1000.0), Some(1000.0))
    );
    // The per-seed mean of incidents differs from seed to seed, so the interval has width.
    let inc = &r["policies"][1]["per_seed_95"]["incidents_per_1000"];
    assert!(inc["low"].as_f64() < inc["high"].as_f64(), "{inc}");
}

#[test]
fn the_report_totals_match_a_run_over_every_seed() {
    let cfg = Config {
        seeds: vec![1, 2, 3],
        ..small(
            vec![
                steady("a", 900),
                Kind {
                    name: "d",
                    before: 990,
                    after: 600,
                },
            ],
            500,
        )
    };
    let r = report(&cfg);
    let t = run(&cfg, Policy::Mohar);
    let m = &r["policies"][3];
    assert_eq!(m["actions"], t.actions);
    assert_eq!(m["promotions"]["to_supervised"], t.promotions[1]);
    assert_eq!(
        m["time_to_demotion"]["drops_measured"],
        t.demotion_delays.len()
    );
}

#[test]
fn a_single_seed_has_no_interval() {
    let r = report(&small(vec![steady("a", 900)], 500));
    assert!(r["policies"][3]["per_seed_95"].is_null());
    assert!(r["prediction"]["wrong_yes_per_1000_per_seed_95"].is_null());
    // The tables then show the totals alone.
    let md = markdown(&r);
    assert!(md.contains("| `always_ask` | 1000.0 | 0.0% |"), "{md}");
    assert!(!md.contains("seed by seed"), "{md}");
}

#[test]
fn the_tables_name_every_policy_with_its_interval() {
    let cfg = Config {
        seeds: vec![1, 2],
        ..person(vec![("src/lib.rs", 990)], 400)
    };
    let cfg = Config {
        kinds: vec![steady("a", 900)],
        agents_per_kind: 2,
        ..cfg
    };
    let md = markdown(&report(&cfg));
    for name in ["always_ask", "static_allowlist", "aggregate_score", "mohar"] {
        assert!(md.contains(&format!("| `{name}` |")), "{md}");
    }
    assert!(
        md.contains("| `always_ask` | 1000.0 (1000.0 to 1000.0) | 0.0% (0.0% to 0.0%) |"),
        "{md}"
    );
    assert!(md.contains("wrong yes answers per 1,000."), "{md}");
    assert!(md.contains("Taken seed by seed, the mean was"), "{md}");
    assert!(md.ends_with('\n'));
}

fn person(habits: Vec<(&'static str, u64)>, escalations: u64) -> Config {
    Config {
        seeds: vec![3, 4],
        escalations,
        habits,
        ..small(Vec::new(), 500)
    }
}

#[test]
fn a_person_who_always_says_yes_is_mostly_answered_for_and_never_wrongly() {
    let a = agreement(&person(
        vec![("src/lib.rs", 1000), ("docs/a.md", 1000)],
        300,
    ));
    assert_eq!(a.escalations, 600);
    assert!(a.predicted > 300, "{a:?}");
    assert_eq!(a.predicted_wrong, 0);
    assert_eq!(a.checks, a.checks_agreed);
    assert_eq!(a.predicted + a.checks + a.asked, a.escalations);
    assert_eq!(a.trained_on, a.asked + a.checks);
}

#[test]
fn a_target_the_person_refuses_is_never_answered_yes() {
    let a = agreement(&person(vec![("docs/a.md", 1000), ("ci.yml", 0)], 300));
    assert!(a.predicted > 0, "{a:?}");
    assert_eq!(a.predicted_wrong, 0);
}

#[test]
fn a_person_who_says_yes_half_the_time_is_always_asked() {
    let a = agreement(&person(vec![("src/lib.rs", 500)], 300));
    assert_eq!(a.predicted + a.checks, 0, "{a:?}");
    assert_eq!(a.asked, 600);
}

#[test]
fn nothing_is_predicted_before_the_person_has_enough_answers() {
    let a = agreement(&person(vec![("src/lib.rs", 1000)], 29));
    assert_eq!(a.asked, 58);
    assert_eq!(a.predicted + a.checks, 0);
}

#[test]
fn some_predictions_still_go_to_the_person_and_train_the_model() {
    let a = agreement(&person(vec![("src/lib.rs", 1000)], 1000));
    assert!(a.checks > 0, "{a:?}");
    assert!(a.checks * 10 < a.predicted, "{a:?}");
}

#[test]
fn a_mostly_yes_person_is_sometimes_answered_wrongly_and_the_report_says_so() {
    let cfg = person(vec![("src/lib.rs", 990)], 1000);
    let a = agreement(&cfg);
    assert!(a.predicted_wrong > 0, "{a:?}");
    let r = report(&cfg);
    let p = &r["prediction"];
    assert_eq!(p["answered_by_model"], a.predicted);
    assert_eq!(p["checks"], a.checks);
    let all = p["agreement_on_all_predictions"].as_f64().unwrap_or(1.0);
    assert!(all < 1.0 && all > 0.9, "{p}");
}

#[test]
fn no_person_no_predictions() {
    assert_eq!(agreement(&person(Vec::new(), 300)), Agreement::default());
    let r = report(&person(vec![("a", 1000)], 0));
    assert_eq!(r["prediction"]["agreement_on_checks"], 0.0);
    assert_eq!(r["prediction"]["wrong_yes_per_1000_predicted"], 0.0);
}

#[test]
fn a_check_can_disagree_with_the_prediction() {
    let a = agreement(&Config {
        seeds: (1..=6).collect(),
        ..person(vec![("src/lib.rs", 990)], 1500)
    });
    assert!(a.checks_agreed < a.checks, "{a:?}");
}

/// Lesson runs: `misleading` agents that plant failures at `plant` per thousand next to `kinds`, and a
/// person who promotes `promote` per thousand fixed lessons and spots `spot` per thousand planted ones.
fn book(kinds: Vec<Kind>, misleading: u64, plant: u64, promote: u64, spot: u64) -> Config {
    Config {
        misleading,
        plant_per_mille: plant,
        promote_per_mille: promote,
        spot_per_mille: spot,
        ..small(kinds, 0)
    }
}

/// Fails everything until the drift day, then passes everything.
fn turnaround() -> Kind {
    Kind {
        name: "turnaround",
        before: 0,
        after: 1000,
    }
}

#[test]
fn honest_agents_write_no_poisoned_lessons() {
    let p = lessons(&book(
        vec![steady("a", 700), steady("b", 900)],
        0,
        0,
        1000,
        0,
    ));
    assert!(p.written > 0 && p.kept > 0 && p.shared > 0, "{p:?}");
    assert_eq!(p.poisoned, 0);
    assert_eq!(p.poisoned_kept, 0);
    assert_eq!(p.poisoned_shared, 0);
}

#[test]
fn every_verified_failure_writes_one_lesson() {
    // One agent that fails everything: 35 days, 6 actions, 3 capabilities.
    let p = lessons(&book(vec![steady("a", 0)], 0, 0, 0, 0));
    assert_eq!(p.written, 35 * 6 * 3);
    // A misleading agent's failures are all planted, so all its lessons are poisoned.
    let p = lessons(&book(Vec::new(), 1, 1000, 0, 0));
    assert_eq!(p.written, 35 * 6 * 3);
    assert_eq!(p.poisoned, p.written);
}

#[test]
fn a_serious_failure_withholds_only_what_the_last_release_did_not_cover() {
    // It fails deploy on every slot, so a quarantine is always open. The person releases it a day
    // after it opens, which covers every lesson up to the previous slot, and the next deploy failure
    // opens a new one. At the end only the last day's lessons are withheld, all 6 slots on 3
    // capabilities, less the last deploy failure's own lesson.
    let p = lessons(&book(vec![steady("a", 0)], 0, 0, 0, 0));
    assert_eq!(p.withheld, 6 * 3 - 1, "{p:?}");
    assert_eq!(p.kept, p.written - p.withheld);
    assert_eq!(p.honest_withheld, p.withheld);
}

#[test]
fn a_quarantine_is_released_a_day_after_the_last_serious_failure() {
    // Its last failure is on day 27 and it passes from day 28 on, so by day 35 the person has reviewed
    // the quarantine and every lesson is back.
    let p = lessons(&book(vec![turnaround()], 0, 0, 0, 0));
    assert_eq!(p.written, 28 * 6 * 3);
    assert_eq!(p.kept, p.written, "{p:?}");
    assert_eq!(p.withheld, 0);
}

#[test]
fn only_promoted_lessons_reach_another_agent() {
    let kinds = vec![turnaround(), steady("b", 900)];
    let none = lessons(&book(kinds.clone(), 2, 300, 0, 0));
    assert_eq!(none.promoted, 0);
    assert_eq!(none.shared, 0);
    assert_eq!(none.poisoned_shared, 0);
    assert!(none.poisoned_kept > 0, "{none:?}");
    let all = lessons(&book(kinds, 2, 300, 1000, 0));
    assert!(all.promoted > 0);
    assert!(all.shared > 0 && all.shared <= all.promoted, "{all:?}");
}

#[test]
fn a_person_who_spots_every_planted_lesson_shares_none() {
    let kinds = vec![steady("a", 800)];
    let blind = lessons(&book(kinds.clone(), 2, 300, 1000, 0));
    assert_eq!(blind.spotted, 0);
    assert!(blind.poisoned_shared > 0, "{blind:?}");
    let sharp = lessons(&book(kinds, 2, 300, 1000, 1000));
    assert!(sharp.spotted > 0, "{sharp:?}");
    assert_eq!(sharp.poisoned_shared, 0);
    // Spotting drops only planted lessons: the honest ones are promoted as before.
    assert_eq!(
        sharp.shared,
        blind.shared - blind.poisoned_shared,
        "{sharp:?} {blind:?}"
    );
}

#[test]
fn the_report_compares_the_book_with_shared_notes() {
    let cfg = Config {
        seeds: vec![1, 2],
        ..book(vec![steady("a", 800)], 1, 200, 500, 500)
    };
    let r = report(&cfg);
    let l = &r["lessons"];
    let mut sum = Poisoning::default();
    for s in [1, 2] {
        let p = lessons(&Config {
            seeds: vec![s],
            ..cfg.clone()
        });
        sum.written += p.written;
        sum.poisoned += p.poisoned;
    }
    assert_eq!(l["written"], sum.written);
    assert_eq!(l["poisoned_written"], sum.poisoned);
    assert_eq!(l["misleading_agents"], 1);
    let notes = &l["shared_notes"];
    assert!(
        notes["poisoned_per_1000_kept"].as_f64().unwrap_or_default() > 0.0,
        "{l}"
    );
    assert_eq!(
        notes["poisoned_per_1000_kept"],
        notes["poisoned_per_1000_shared"]
    );
    let m = &l["mohar"];
    for k in [
        "kept",
        "poisoned_kept",
        "poisoned_per_1000_kept",
        "shared",
        "poisoned_shared",
        "poisoned_per_1000_shared",
        "promoted",
        "spotted",
        "withheld",
    ] {
        assert!(m.get(k).is_some(), "{k} missing from {m}");
    }
    for k in ["poisoned_per_1000_kept", "poisoned_per_1000_shared"] {
        assert!(m["per_seed_95"][k].is_object(), "{k}: {m}");
        assert!(notes["per_seed_95"][k].is_object(), "{k}: {notes}");
    }
    let md = markdown(&r);
    assert!(md.contains("| Memory | Lessons kept |"), "{md}");
    assert!(md.contains("| shared notes |"), "{md}");
    assert!(md.contains("| `mohar` lesson book |"), "{md}");
}

#[test]
fn no_lessons_reports_zeros() {
    let r = report(&book(Vec::new(), 0, 0, 0, 0));
    assert_eq!(r["lessons"]["written"], 0);
    assert_eq!(r["lessons"]["mohar"]["poisoned_per_1000_kept"], 0.0);
}
