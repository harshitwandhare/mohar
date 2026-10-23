//! Trust per agent per capability, earned from verified outcomes and lost in proportion to what a
//! failure could have cost (docs/design.md, section 4).
//!
//! Everything here is a pure function of the events fed in and the time passed in, so the whole state
//! can be rebuilt by replaying the signed log through it, and every rule can be tested exactly.

use std::collections::{BTreeMap, BTreeSet};

use crate::policy::{Capability, Risk};

/// Seconds in a day.
const DAY: u64 = 86_400;
/// Evidence loses half its weight every 30 days.
const HALF_LIFE_DAYS: f64 = 30.0;
/// z for a two-sided 95% interval.
const Z: f64 = 1.959_963_984_540_054;
/// Days at a level before promotion out of it.
const MIN_DAYS_AT_LEVEL: u64 = 7;
/// Days since the last serious (S3 or S4) failure before any promotion.
const GATE_QUIET_DAYS: u64 = 14;
/// Minor failures on one capability within this many days that together count as a meaningful one.
const MINOR_WINDOW_DAYS: u64 = 14;
const MINORS_FOR_MEANINGFUL: usize = 3;
/// Consecutive verified passes that end remediation.
pub const REMEDIATION_PASSES: u32 = 5;

/// The three trust levels.
pub const ASK_FIRST: u8 = 0;
/// Low-risk reversible actions run; the rest go to a person.
pub const SUPERVISED: u8 = 1;
/// Actions run inside the capability's gates.
pub const TRUSTED: u8 = 2;

/// What promotion to each level needs: (minimum verified outcomes, Wilson lower bound).
const PROMOTE_TO: [(f64, f64); 3] = [(0.0, 0.0), (10.0, 0.80), (30.0, 0.95)];

/// How serious a failure was, by what it could have cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Stopped before it ran; it would have been a mistake.
    S0,
    /// Low-risk, reversible, caught before it landed.
    S1,
    /// Reversible but meaningful, or on a medium-risk capability.
    S2,
    /// A gate violation, an irreversible change, or a failure on a high-risk capability.
    S3,
    /// Tampering, an attempt to reach an unlisted host, or receipts that don't verify.
    S4,
}

impl Severity {
    /// The class a failure on this capability gets when nothing more specific is known.
    pub fn for_capability(spec: &Capability) -> Self {
        if spec.risk == Risk::High || !spec.reversible {
            Severity::S3
        } else if spec.risk == Risk::Medium {
            Severity::S2
        } else {
            Severity::S1
        }
    }
}

/// One verified outcome on a capability.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// When it was verified, in seconds since the Unix epoch.
    pub at: u64,
    /// Whether the verifier passed it.
    pub passed: bool,
    /// For a failure, how serious it was.
    pub severity: Severity,
    /// Whether a pass exercised the failure that caused the current remediation.
    pub exercises_failure: bool,
    /// Capabilities that share this one's scope (the same paths, hosts or database): an S3 drops them
    /// too.
    pub related: Vec<String>,
}

/// Why an action was decided the way it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// `allow`, `escalate` or `deny`.
    pub result: &'static str,
    /// The level the decision was made at.
    pub level: u8,
}

#[derive(Debug, Clone, Default)]
struct Record {
    level: u8,
    /// When the current level was entered.
    since: u64,
    /// (time, passed) for every verified outcome, oldest first.
    outcomes: Vec<(u64, bool)>,
    /// Times of minor failures, for the three-in-fourteen-days rule.
    minors: Vec<u64>,
    /// When the last serious (S3 or S4) failure happened.
    last_serious: Option<u64>,
    /// Consecutive passes still needed to leave remediation, and whether one of them must exercise the
    /// failure that caused it.
    remediation: Option<(u32, bool)>,
}

/// Trust state for every agent and capability.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    records: BTreeMap<(String, String), Record>,
    suspended: BTreeSet<String>,
}

/// Weight of evidence `age` seconds old.
fn weight(age: u64) -> f64 {
    0.5_f64.powf(age as f64 / DAY as f64 / HALF_LIFE_DAYS)
}

/// Lower bound of the 95% Wilson score interval for `s` successes out of `s + f`.
pub fn wilson_lower(s: f64, f: f64) -> f64 {
    let n = s + f;
    if n <= 0.0 {
        return 0.0;
    }
    let p = s / n;
    let z2 = Z * Z;
    let centre = p + z2 / (2.0 * n);
    let spread = Z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt();
    ((centre - spread) / (1.0 + z2 / n)).max(0.0)
}

impl Ledger {
    /// An empty ledger: every agent starts at Ask first on every capability.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(agent: &str, capability: &str) -> (String, String) {
        (agent.to_string(), capability.to_string())
    }

    /// The agent's level on a capability right now, after any promotion it has earned.
    pub fn level(&mut self, agent: &str, capability: &str, spec: &Capability, now: u64) -> u8 {
        if self.suspended.contains(agent) {
            return ASK_FIRST;
        }
        let r = self
            .records
            .entry(Self::key(agent, capability))
            .or_default();
        // Promotion one step at a time; each step resets the clock, so the next one waits again.
        while r.level < spec.ceiling.min(TRUSTED) && eligible(r, spec, now) {
            r.level += 1;
            r.since = now;
        }
        r.level.min(spec.ceiling)
    }

    /// Decide an action on a capability: what runs, what goes to a person, what is refused.
    pub fn decide(
        &mut self,
        agent: &str,
        capability: &str,
        spec: &Capability,
        now: u64,
    ) -> Verdict {
        if self.suspended.contains(agent) {
            return Verdict {
                result: "deny",
                level: ASK_FIRST,
            };
        }
        if spec.risk == Risk::None {
            return Verdict {
                result: "allow",
                level: self.level(agent, capability, spec, now),
            };
        }
        let level = self.level(agent, capability, spec, now);
        // Whatever the level, an irreversible high-impact action reaches a person.
        let result = if spec.risk == Risk::High && !spec.reversible {
            "escalate"
        } else {
            match level {
                TRUSTED => "allow",
                SUPERVISED if spec.risk == Risk::Low && spec.reversible => "allow",
                _ => "escalate",
            }
        };
        Verdict { result, level }
    }

    /// Record a verified outcome. Demotion happens here, immediately; promotion waits for `level`.
    pub fn record(&mut self, agent: &str, capability: &str, o: &Outcome) {
        if !o.passed && o.severity == Severity::S4 {
            self.suspended.insert(agent.to_string());
        }
        let r = self
            .records
            .entry(Self::key(agent, capability))
            .or_default();
        r.outcomes.push((o.at, o.passed));
        if o.passed {
            if let Some((left, needs_exercise)) = r.remediation {
                let needs = needs_exercise && !o.exercises_failure;
                r.remediation = match left.saturating_sub(1) {
                    0 if !needs => None,
                    // The last pass didn't exercise the failure; one more is needed that does.
                    0 => Some((1, true)),
                    n => Some((n, needs)),
                };
            }
            return;
        }
        let mut severity = o.severity;
        if severity == Severity::S1 {
            r.minors
                .retain(|t| o.at.saturating_sub(*t) <= MINOR_WINDOW_DAYS * DAY);
            r.minors.push(o.at);
            if r.minors.len() >= MINORS_FOR_MEANINGFUL {
                r.minors.clear();
                severity = Severity::S2;
            }
        }
        match severity {
            Severity::S0 | Severity::S1 => {}
            Severity::S2 => {
                r.level = r.level.saturating_sub(1);
                r.since = o.at;
                r.remediation = Some((REMEDIATION_PASSES, true));
            }
            Severity::S3 | Severity::S4 => {
                r.level = ASK_FIRST;
                r.since = o.at;
                r.last_serious = Some(o.at);
                r.remediation = Some((REMEDIATION_PASSES, true));
                if severity == Severity::S3 {
                    for other in &o.related {
                        let rr = self.records.entry(Self::key(agent, other)).or_default();
                        rr.level = ASK_FIRST;
                        rr.since = o.at;
                        rr.remediation = Some((REMEDIATION_PASSES, false));
                    }
                }
            }
        }
    }

    /// Whether an agent is suspended on every capability.
    pub fn is_suspended(&self, agent: &str) -> bool {
        self.suspended.contains(agent)
    }

    /// Lift a suspension. Only a person does this, and the caller records it as a receipt.
    pub fn reinstate(&mut self, agent: &str) {
        self.suspended.remove(agent);
    }

    /// Whether a capability is in remediation for an agent.
    pub fn in_remediation(&self, agent: &str, capability: &str) -> bool {
        self.records
            .get(&Self::key(agent, capability))
            .is_some_and(|r| r.remediation.is_some())
    }
}

/// Whether the record has earned one step up from its current level.
fn eligible(r: &Record, spec: &Capability, now: u64) -> bool {
    let next = usize::from(r.level) + 1;
    // `level` never asks past Trusted, so this only keeps the function total.
    let Some(&(n_min, bound)) = PROMOTE_TO.get(next) else {
        return false;
    };
    if r.remediation.is_some() || now.saturating_sub(r.since) < MIN_DAYS_AT_LEVEL * DAY {
        return false;
    }
    if r.last_serious
        .is_some_and(|t| now.saturating_sub(t) < GATE_QUIET_DAYS * DAY)
    {
        return false;
    }
    // High-risk irreversible capabilities never reach Trusted.
    if next == usize::from(TRUSTED) && spec.risk == Risk::High && !spec.reversible {
        return false;
    }
    let (mut s, mut f) = (0.0, 0.0);
    for &(at, passed) in &r.outcomes {
        let w = weight(now.saturating_sub(at));
        if passed {
            s += w;
        } else {
            f += w;
        }
    }
    // The minimum count is over weighted evidence, so old outcomes count for less there too.
    s + f >= n_min && wilson_lower(s, f) >= bound
}
