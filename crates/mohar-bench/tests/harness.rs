//! Checks on the benchmark harness: that it is repeatable, that every policy sees the same tasks, and
//! that each metric counts what it says on agents whose behaviour is known exactly.

use mohar_bench::{Config, Kind, Policy, false_promotion, level_bound, report, run};

fn small(kinds: Vec<Kind>, catch: u64) -> Config {
    Config {
        seeds: vec![7],
        days: 35,
        actions_per_day: 6,
        kinds,
        agents_per_kind: 1,
        drift_day: 28,
        catch_per_mille: catch,
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
    // The drop comes on the last day and every failure is stopped by a person: nothing is recorded,
    // so nothing demotes before the run ends. Only deploy is still asked about at Supervised.
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
    assert_eq!(t.never_demoted, 1);
}

#[test]
fn stopped_failures_are_not_evidence_so_a_poor_agent_can_be_promoted() {
    // A 70% agent whose failures are all stopped at Ask first shows only passes, and Mohar promotes it
    // to Supervised, which stands for 80%. The harness counts that as a false promotion.
    let cfg = small(vec![steady("poor", 700)], 1000);
    let t = run(&cfg, Policy::Mohar);
    assert!(t.false_promotions[1] > 0);
    assert_eq!(t.false_promotions[1], t.promotions[1]);
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
