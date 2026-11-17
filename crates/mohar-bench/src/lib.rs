//! Benchmark harness for Mohar's trust rules (docs/design.md section 10).
//!
//! Simulated agents of known quality work on recurring tasks whose outcome a verifier decides, for a
//! number of simulated weeks. The same task outcomes go through Mohar's per-capability ledger and
//! through three baselines: always ask, a static allowlist, and one aggregate score per agent. The run
//! reports how often each policy asks a person, how many failures ran without a person stopping them,
//! how often an agent was promoted to a level its real pass rate doesn't meet, and how many actions a
//! real drop in quality went on for before the agent was demoted. A second part, [`agreement`], runs the
//! per-person answer model against a simulated person and reports how often its answers match theirs.
//!
//! A run is a pure function of its [`Config`]. Each task's outcome comes from hashing (seed, agent,
//! capability, action), so every policy sees the same tasks and anyone can regenerate the results:
//! `MOHAR_WRITE_BENCH=1 cargo test --release -p mohar-bench` rewrites `results.json`.

use std::collections::BTreeMap;

use mohar_core::policy::{Capability, Risk};
use mohar_core::predict::{self, Limits, Model, Past, Prediction, Request};
use mohar_core::trust::{Ledger, Outcome, Severity};
use serde_json::{Value, json};

/// Seconds in a day.
const DAY: u64 = 86_400;
/// Simulated time starts at 2027-01-01T00:00:00Z.
const START: u64 = 1_798_761_600;

/// An agent's quality: its real pass rate per thousand actions before and after the drift day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kind {
    /// Name used in agent ids and in the results.
    pub name: &'static str,
    /// Passes per thousand before the drift day.
    pub before: u64,
    /// Passes per thousand from the drift day on. Lower than `before` for an agent whose quality drops.
    pub after: u64,
}

/// One benchmark run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// One simulation per seed; results are summed over them.
    pub seeds: Vec<u64>,
    /// Simulated days.
    pub days: u64,
    /// Actions per agent per capability per day.
    pub actions_per_day: u64,
    /// The kinds of agent, each run as `agents_per_kind` separate agents.
    pub kinds: Vec<Kind>,
    /// Agents of each kind.
    pub agents_per_kind: u64,
    /// The day quality changes for kinds whose `after` differs from `before`.
    pub drift_day: u64,
    /// Failing actions per thousand that a person who is asked stops before they run. A stopped action
    /// has no outcome; the person refuses it as wrong, which the daemon counts against the agent.
    pub catch_per_mille: u64,
    /// Escalations per seed on `edit` that one simulated person answers, for the prediction agreement
    /// part of the run. Zero skips it.
    pub escalations: u64,
    /// That person's habits: a target and how many times per thousand they say yes to an edit of it.
    pub habits: Vec<(&'static str, u64)>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            seeds: (1..=8).collect(),
            days: 63,
            actions_per_day: 6,
            kinds: vec![
                Kind {
                    name: "good",
                    before: 980,
                    after: 980,
                },
                Kind {
                    name: "middling",
                    before: 870,
                    after: 870,
                },
                Kind {
                    name: "poor",
                    before: 750,
                    after: 750,
                },
                Kind {
                    name: "drifting",
                    before: 980,
                    after: 700,
                },
            ],
            agents_per_kind: 5,
            drift_day: 28,
            catch_per_mille: 500,
            escalations: 400,
            habits: vec![
                ("docs/guide.md", 1000),
                ("tests/run.rs", 990),
                ("src/lib.rs", 970),
                ("src/cli.rs", 950),
                (".github/workflows/ci.yml", 200),
            ],
        }
    }
}

/// How actions are decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Every action goes to a person.
    AlwaysAsk,
    /// Low-risk reversible capabilities run; everything else goes to a person.
    Allowlist,
    /// Mohar's rules over one score per agent, pooled across capabilities.
    Aggregate,
    /// Mohar's rules, one score per agent per capability.
    Mohar,
}

impl Policy {
    /// Every policy, in the order the results list them.
    pub const ALL: [Policy; 4] = [
        Policy::AlwaysAsk,
        Policy::Allowlist,
        Policy::Aggregate,
        Policy::Mohar,
    ];

    /// Its name in the results.
    pub fn name(self) -> &'static str {
        match self {
            Policy::AlwaysAsk => "always_ask",
            Policy::Allowlist => "static_allowlist",
            Policy::Aggregate => "aggregate_score",
            Policy::Mohar => "mohar",
        }
    }
}

/// The capabilities every agent works on: cheap and reversible, meaningful but reversible, and costly
/// and irreversible (the last never above Supervised).
pub fn capabilities() -> [(&'static str, Capability); 3] {
    [
        (
            "edit",
            Capability {
                risk: Risk::Low,
                reversible: true,
                ceiling: 2,
            },
        ),
        (
            "deps",
            Capability {
                risk: Risk::Medium,
                reversible: true,
                ceiling: 2,
            },
        ),
        (
            "deploy",
            Capability {
                risk: Risk::High,
                reversible: false,
                ceiling: 1,
            },
        ),
    ]
}

/// The real pass rate, per thousand, a level is meant to stand for: Supervised is promoted on a 95%
/// lower bound of 0.80 and Trusted on 0.95 (trust.rs `PROMOTE_TO`).
pub fn level_bound(level: u8) -> u64 {
    match level {
        0 => 0,
        1 => 800,
        _ => 950,
    }
}

/// Whether a promotion to `level` was false: the agent's real pass rate at the time is below what the
/// level stands for.
pub fn false_promotion(level: u8, pass_per_mille: u64) -> bool {
    pass_per_mille < level_bound(level)
}

/// What one policy did over every seed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// Actions the agents tried.
    pub actions: u64,
    /// Actions that went to a person.
    pub prompts: u64,
    /// Failing actions that ran without a person stopping them.
    pub incidents: u64,
    /// Incidents on the irreversible high-risk capability.
    pub serious_incidents: u64,
    /// Promotions, by the level reached (index 1 is Supervised, 2 is Trusted).
    pub promotions: [u64; 3],
    /// Promotions to a level the agent's real pass rate didn't meet, by level.
    pub false_promotions: [u64; 3],
    /// For each agent and capability whose quality dropped while above Ask first: actions run at the
    /// old level after the drop, until the demotion showed. Empty for the policies without levels.
    pub demotion_delays: Vec<u64>,
    /// Drops in quality that came while the agent was still at Ask first, so there was nothing to
    /// demote.
    pub drops_at_ask_first: u64,
    /// Drops in quality never followed by a demotion before the run ended.
    pub never_demoted: u64,
}

/// A number in [0, 1000), the same for the same parts.
fn draw(parts: &[u64]) -> u64 {
    parts.iter().fold(0, |h, &p| mix(h ^ p)) % 1000
}

/// splitmix64's finaliser.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Where an agent stands on one capability under a policy with levels.
#[derive(Debug, Clone, Copy, Default)]
struct Track {
    /// The level the last decision was made at.
    level: u8,
    /// Set at the drop in quality: the level then, and the actions since.
    drop: Option<(u8, u64)>,
    /// The drop has been measured.
    done: bool,
}

/// Run one policy over every seed in `cfg`.
pub fn run(cfg: &Config, policy: Policy) -> Tally {
    let caps = capabilities();
    let mut t = Tally::default();
    for &seed in &cfg.seeds {
        let mut ledger = Ledger::new();
        let mut tracks: BTreeMap<(u64, usize), Track> = BTreeMap::new();
        for day in 0..cfg.days {
            for slot in 0..cfg.actions_per_day {
                let now = START + day * DAY + slot * (DAY / cfg.actions_per_day);
                let n = day * cfg.actions_per_day + slot;
                for (k, kind) in cfg.kinds.iter().enumerate() {
                    let pass_rate = if day < cfg.drift_day {
                        kind.before
                    } else {
                        kind.after
                    };
                    for i in 0..cfg.agents_per_kind {
                        let agent_no = k as u64 * cfg.agents_per_kind + i;
                        let agent = format!("{}-{i}", kind.name);
                        for (c, (cap, spec)) in caps.iter().enumerate() {
                            let key = match policy {
                                Policy::Aggregate => "all",
                                _ => cap,
                            };
                            let level = match policy {
                                Policy::AlwaysAsk => None,
                                Policy::Allowlist => None,
                                Policy::Aggregate | Policy::Mohar => {
                                    Some(ledger.decide(&agent, key, spec, now))
                                }
                            };
                            let ask = match (&level, policy) {
                                (Some(v), _) => v.result != "allow",
                                (None, Policy::Allowlist) => {
                                    !(spec.risk == Risk::Low && spec.reversible)
                                }
                                (None, _) => true,
                            };
                            if let Some(v) = &level {
                                let tr = tracks.entry((agent_no, c)).or_default();
                                observe(&mut t, tr, v.level, pass_rate);
                                if day == cfg.drift_day && slot == 0 && kind.after < kind.before {
                                    if tr.level == 0 {
                                        t.drops_at_ask_first += 1;
                                        tr.done = true;
                                    } else {
                                        tr.drop = Some((tr.level, 0));
                                    }
                                }
                                if let Some((at, ran)) = &mut tr.drop
                                    && !tr.done
                                {
                                    if v.level < *at {
                                        t.demotion_delays.push(*ran);
                                        tr.done = true;
                                    } else {
                                        *ran += 1;
                                    }
                                }
                            }
                            let passed = draw(&[seed, agent_no, c as u64, n, 0]) < pass_rate;
                            let caught =
                                draw(&[seed, agent_no, c as u64, n, 1]) < cfg.catch_per_mille;
                            t.actions += 1;
                            t.prompts += u64::from(ask);
                            // A person who is asked stops a failing action they catch; it never runs.
                            // They refuse it as wrong, so it is still evidence against the agent.
                            if ask && !passed && caught {
                                if level.is_some() {
                                    ledger.refused_wrong(&agent, key, now);
                                }
                                continue;
                            }
                            if !passed {
                                t.incidents += 1;
                                t.serious_incidents +=
                                    u64::from(spec.risk == Risk::High && !spec.reversible);
                            }
                            if level.is_some() {
                                ledger.record(
                                    &agent,
                                    key,
                                    &Outcome {
                                        at: now,
                                        passed,
                                        severity: Severity::for_capability(spec),
                                        // Tasks recur, so a pass after a failure is on the same task.
                                        exercises_failure: passed,
                                        related: Vec::new(),
                                        verifier: "tests".to_string(),
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        for tr in tracks.values() {
            t.never_demoted += u64::from(tr.drop.is_some() && !tr.done);
        }
    }
    t
}

/// Note a decision's level: count a promotion, and whether it was false.
fn observe(t: &mut Tally, tr: &mut Track, level: u8, pass_rate: u64) {
    if level > tr.level {
        let l = usize::from(level);
        t.promotions[l] += 1;
        t.false_promotions[l] += u64::from(false_promotion(level, pass_rate));
    }
    tr.level = level;
}

/// Rounded to four places, so results files don't churn in the last digit.
fn round(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// `part` per thousand of `whole`, or zero when there is no whole.
fn per_thousand(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        round(part as f64 * 1000.0 / whole as f64)
    }
}

/// `part` as a share of `whole`, or zero when there is no whole.
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        round(part as f64 / whole as f64)
    }
}

/// The value at quantile `q` of `xs` (nearest rank), or zero when empty.
fn quantile(xs: &[u64], q: f64) -> u64 {
    let mut v = xs.to_vec();
    v.sort_unstable();
    match v.len() {
        0 => 0,
        n => v[((q * n as f64).ceil() as usize).clamp(1, n) - 1],
    }
}

/// Answers between retraining the person's model, as a daemon would retrain in batches.
pub const RETRAIN_EVERY: usize = 25;

/// What the answer model did for the simulated person over every seed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Agreement {
    /// Escalations the person could have been asked.
    pub escalations: u64,
    /// Answered yes by the model; the person never saw them.
    pub predicted: u64,
    /// Of those, ones the person would have refused.
    pub predicted_wrong: u64,
    /// Predictions drawn as checks, so the person answered anyway.
    pub checks: u64,
    /// Checks where the person said yes, as predicted.
    pub checks_agreed: u64,
    /// Escalations the person answered because the model wasn't allowed or wasn't sure.
    pub asked: u64,
    /// Answers the model learned from, summed over seeds.
    pub trained_on: u64,
}

/// Run the answer model (`mohar_core::predict`) against one simulated person whose real answers are
/// known, so agreement is measured on every prediction, not only on the checks a daemon can see. As in
/// the daemon, the model trains only on answers the person gave (asked and checks).
pub fn agreement(cfg: &Config) -> Agreement {
    let [(_, edit), ..] = capabilities();
    let limits = BTreeMap::from([(
        "edit".to_string(),
        Limits {
            paths: vec!["**".to_string()],
            per_day: u32::MAX,
        },
    )]);
    let mut a = Agreement::default();
    if cfg.habits.is_empty() {
        return a;
    }
    for &seed in &cfg.seeds {
        let mut check_seed = [0u8; 32];
        check_seed[..8].copy_from_slice(&seed.to_le_bytes());
        let mut past: Vec<Past> = Vec::new();
        let mut model: Option<Model> = None;
        for n in 0..cfg.escalations {
            let (target, yes_rate) = cfg.habits[(draw(&[seed, n, 2]) as usize) % cfg.habits.len()];
            let yes = draw(&[seed, n, 3]) < yes_rate;
            let req = Request {
                capability: "edit",
                spec: &edit,
                target,
                used_today: 0,
                p_yes: model
                    .as_ref()
                    .map(|m| m.p_yes(&past, "edit", Risk::Low, target)),
            };
            a.escalations += 1;
            match predict::decide(&req, &limits, &check_seed, n) {
                Prediction::Yes { .. } => {
                    a.predicted += 1;
                    a.predicted_wrong += u64::from(!yes);
                    continue;
                }
                Prediction::Check { .. } => {
                    a.checks += 1;
                    a.checks_agreed += u64::from(yes);
                }
                Prediction::Ask(_) => a.asked += 1,
            }
            past.push(Past {
                capability: "edit".to_string(),
                risk: Risk::Low,
                target: target.to_string(),
                yes,
            });
            if past.len().is_multiple_of(RETRAIN_EVERY) {
                model = Model::train(&past);
            }
        }
        a.trained_on += past.len() as u64;
    }
    a
}

/// Run every policy and report, as the JSON written to `results.json`.
pub fn report(cfg: &Config) -> Value {
    let tallies: Vec<(Policy, Tally)> = Policy::ALL.iter().map(|&p| (p, run(cfg, p))).collect();
    let ask_all = tallies[0].1.prompts;
    let allowlist_incidents = per_thousand(tallies[1].1.incidents, tallies[1].1.actions);
    let policies: Vec<Value> = tallies
        .iter()
        .map(|(p, t)| {
            let incidents = per_thousand(t.incidents, t.actions);
            let mut v = json!({
                "policy": p.name(),
                "actions": t.actions,
                "prompts_per_1000": per_thousand(t.prompts, t.actions),
                "prompts_avoided_vs_always_ask": share(ask_all - t.prompts, ask_all),
                "incidents_per_1000": incidents,
                "serious_incidents_per_1000": per_thousand(t.serious_incidents, t.actions),
                "incidents_at_or_below_allowlist": incidents <= allowlist_incidents,
            });
            if matches!(p, Policy::Aggregate | Policy::Mohar) {
                let all: u64 = t.promotions.iter().sum();
                let false_all: u64 = t.false_promotions.iter().sum();
                v["promotions"] = json!({
                    "to_supervised": t.promotions[1],
                    "to_trusted": t.promotions[2],
                    "false_to_supervised": t.false_promotions[1],
                    "false_to_trusted": t.false_promotions[2],
                    "false_promotion_rate": share(false_all, all),
                });
                v["time_to_demotion"] = json!({
                    "drops_measured": t.demotion_delays.len(),
                    "median_actions": quantile(&t.demotion_delays, 0.5),
                    "p90_actions": quantile(&t.demotion_delays, 0.9),
                    "max_actions": quantile(&t.demotion_delays, 1.0),
                    "drops_at_ask_first": t.drops_at_ask_first,
                    "never_demoted": t.never_demoted,
                });
            }
            v
        })
        .collect();
    let caps: Vec<Value> = capabilities()
        .iter()
        .map(|(name, s)| {
            json!({
                "name": name,
                "risk": format!("{:?}", s.risk).to_lowercase(),
                "reversible": s.reversible,
                "ceiling": s.ceiling,
            })
        })
        .collect();
    let kinds: Vec<Value> = cfg
        .kinds
        .iter()
        .map(|k| json!({"name": k.name, "pass_per_1000_before": k.before, "pass_per_1000_after": k.after}))
        .collect();
    json!({
        "harness": "mohar-bench",
        "config": {
            "seeds": cfg.seeds,
            "days": cfg.days,
            "actions_per_day_per_capability": cfg.actions_per_day,
            "agents_per_kind": cfg.agents_per_kind,
            "drift_day": cfg.drift_day,
            "catch_per_1000": cfg.catch_per_mille,
            "kinds": kinds,
            "capabilities": caps,
        },
        "policies": policies,
        "prediction": prediction(cfg),
    })
}

/// The prediction agreement part of the report.
fn prediction(cfg: &Config) -> Value {
    let a = agreement(cfg);
    let habits: Vec<Value> = cfg
        .habits
        .iter()
        .map(|(t, y)| json!({"target": t, "yes_per_1000": y}))
        .collect();
    json!({
        "escalations_per_seed": cfg.escalations,
        "retrain_every": RETRAIN_EVERY,
        "threshold": predict::THRESHOLD,
        "habits": habits,
        "escalations": a.escalations,
        "answered_by_model": a.predicted,
        "answered_by_model_share": share(a.predicted, a.escalations),
        "checks": a.checks,
        "agreement_on_checks": share(a.checks_agreed, a.checks),
        "agreement_on_all_predictions": share(
            a.predicted - a.predicted_wrong + a.checks_agreed,
            a.predicted + a.checks
        ),
        "wrong_yes_per_1000_predicted": per_thousand(a.predicted_wrong, a.predicted),
        "asked": a.asked,
        "answers_given": a.trained_on,
    })
}
