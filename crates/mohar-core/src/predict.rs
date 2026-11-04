//! A person's answers, learned (docs/design.md section 6, "Learning a person's answers").
//!
//! [`Model`] is a logistic regression over one person's past yes and no answers, calibrated with
//! Platt scaling fitted on out-of-fold scores. [`decide`] is the rule for when it may answer for the
//! person: only on a low-risk reversible capability the person switched prediction on for, inside the
//! paths and daily count they set, and only when the calibrated probability of yes is at least
//! [`THRESHOLD`]. It only ever answers yes; anything else goes to the person. One prediction in twenty
//! still goes to the person as a check.
//!
//! Everything here is a pure function of its inputs, so a decision can be recomputed from the log.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::policy::{Capability, Risk, glob};

/// The calibrated probability of yes the model needs before it may answer for the person.
pub const THRESHOLD: f64 = 0.98;
/// Predictions per thousand that still go to the person.
pub const CHECK_PER_MILLE: u64 = 50;
/// Answers a person must have given before there is a model at all.
pub const MIN_ANSWERS: usize = 30;
/// Only the most recent answers train the model, which bounds training time and lets old habits go.
pub const MAX_ANSWERS: usize = 1000;

/// Hashed feature slots.
const DIM: usize = 1024;
/// Past answers on the same capability that make up the "recent history" feature.
const RECENT: usize = 10;
const FOLDS: usize = 5;
const EPOCHS: usize = 500;
const RATE: f64 = 0.5;
const L2: f64 = 0.01;
const PLATT_EPOCHS: usize = 3000;

/// One answer a person gave, oldest first in any slice passed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Past {
    /// The capability of the action they were asked about.
    pub capability: String,
    /// Its risk tier at the time.
    pub risk: Risk,
    /// The action's target, as a path relative to the project root.
    pub target: String,
    /// Whether they said yes.
    pub yes: bool,
}

/// A trained, calibrated model of one person's answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Model {
    w: Vec<f64>,
    /// Platt scaling: P(yes) = sigmoid(a * score + b).
    a: f64,
    b: f64,
}

type Features = Vec<(usize, f64)>;

impl Model {
    /// Trains on `past`, oldest first, using the last [`MAX_ANSWERS`]. Returns `None` with fewer than
    /// [`MIN_ANSWERS`], so a person with a short record is always asked.
    pub fn train(past: &[Past]) -> Option<Self> {
        let past = &past[past.len().saturating_sub(MAX_ANSWERS)..];
        if past.len() < MIN_ANSWERS {
            return None;
        }
        let rows: Vec<(Features, bool)> = (0..past.len())
            .map(|i| {
                let p = &past[i];
                (
                    features(&past[..i], &p.capability, p.risk, &p.target),
                    p.yes,
                )
            })
            .collect();
        // Out-of-fold scores: each answer is scored by a model that never saw it, so the calibration
        // below learns how far the raw scores can be trusted on answers they weren't fitted to.
        let mut held_out = vec![0.0; rows.len()];
        for fold in 0..FOLDS {
            let train: Vec<&(Features, bool)> = rows
                .iter()
                .enumerate()
                .filter(|(i, _)| fold_of(*i) != fold)
                .map(|(_, r)| r)
                .collect();
            let w = fit(&train);
            for (i, r) in rows.iter().enumerate() {
                if fold_of(i) == fold {
                    held_out[i] = score(&w, &r.0);
                }
            }
        }
        let (a, b) = platt(&held_out, &rows.iter().map(|r| r.1).collect::<Vec<_>>());
        Some(Self {
            w: fit(&rows.iter().collect::<Vec<_>>()),
            a,
            b,
        })
    }

    /// The calibrated probability that the person says yes to an action on `capability` at `target`,
    /// given their answers so far (`past`, oldest first).
    pub fn p_yes(&self, past: &[Past], capability: &str, risk: Risk, target: &str) -> f64 {
        sigmoid(self.a * score(&self.w, &features(past, capability, risk, target)) + self.b)
    }
}

/// What a person allows the model to answer for them on one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Path globs the target must match (`*`, `**`, `?`). Empty allows nothing.
    pub paths: Vec<String>,
    /// Predicted answers a day at most.
    pub per_day: u32,
}

/// An escalated action the model might answer.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Its capability.
    pub capability: &'a str,
    /// What that capability is.
    pub spec: &'a Capability,
    /// Its target, relative to the project root.
    pub target: &'a str,
    /// Predicted answers already given for this person today.
    pub used_today: u32,
    /// The model's calibrated probability of yes, or `None` when the person has no model.
    pub p_yes: Option<f64>,
}

/// What happens to an escalated action.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Prediction {
    /// The model answers yes for the person; the receipt says the answer was predicted.
    Yes {
        /// The calibrated probability it answered on.
        p_yes: f64,
    },
    /// The model would have answered yes, but this one was drawn as a check: the person answers, and
    /// the prediction is kept to measure how often the two agree.
    Check {
        /// The calibrated probability it would have answered on.
        p_yes: f64,
    },
    /// The person answers.
    Ask(Why),
}

/// Why the person is asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The capability is above low risk or can't be undone.
    Risky,
    /// The person hasn't switched prediction on for this capability.
    NotEnabled,
    /// The target is outside the paths the person set.
    OutsideLimits,
    /// The person's daily count of predicted answers is used up.
    DailyLimit,
    /// The person has too few answers for a model.
    NoModel,
    /// The model isn't sure enough.
    Unsure,
}

/// Whether the model may answer `req` for the person whose `limits` these are. `seed` and `seq` draw
/// the checks the same way review sampling is drawn: a hash the agent can't predict without the seed,
/// recomputable from the log.
pub fn decide(
    req: &Request<'_>,
    limits: &BTreeMap<String, Limits>,
    seed: &[u8; 32],
    seq: u64,
) -> Prediction {
    if req.spec.risk > Risk::Low || !req.spec.reversible {
        return Prediction::Ask(Why::Risky);
    }
    let Some(l) = limits.get(req.capability) else {
        return Prediction::Ask(Why::NotEnabled);
    };
    if !l
        .paths
        .iter()
        .any(|p| glob(p.as_bytes(), req.target.as_bytes(), true))
    {
        return Prediction::Ask(Why::OutsideLimits);
    }
    if req.used_today >= l.per_day {
        return Prediction::Ask(Why::DailyLimit);
    }
    let Some(p_yes) = req.p_yes else {
        return Prediction::Ask(Why::NoModel);
    };
    // NaN compares as None, so it is unsure too.
    if p_yes.partial_cmp(&THRESHOLD).is_none_or(|o| o.is_lt()) {
        return Prediction::Ask(Why::Unsure);
    }
    if drawn_for_check(seed, seq) {
        Prediction::Check { p_yes }
    } else {
        Prediction::Yes { p_yes }
    }
}

fn drawn_for_check(seed: &[u8; 32], seq: u64) -> bool {
    // Its own tag, so checks are drawn independently of review samples from the same seed.
    let digest = Sha256::new()
        .chain_update(b"mohar prediction check v1")
        .chain_update(seed)
        .chain_update(seq.to_be_bytes())
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % 1000 < CHECK_PER_MILLE
}

/// Capability, risk, the target's top directory and extension, and the share of yes among the
/// person's last [`RECENT`] answers on the same capability (scaled to -1..1, 0 with none).
fn features(past: &[Past], capability: &str, risk: Risk, target: &str) -> Features {
    let (dir, file) = match target.split_once('/') {
        Some((d, _)) => (d, target.rsplit('/').next().unwrap_or_default()),
        None => ("", target),
    };
    let ext = file.rsplit_once('.').map_or("", |(_, e)| e);
    let recent: Vec<bool> = past
        .iter()
        .rev()
        .filter(|p| p.capability == capability)
        .take(RECENT)
        .map(|p| p.yes)
        .collect();
    let history = if recent.is_empty() {
        0.0
    } else {
        2.0 * recent.iter().filter(|&&y| y).count() as f64 / recent.len() as f64 - 1.0
    };
    vec![
        (0, 1.0),
        (slot("cap", capability), 1.0),
        (slot("risk", &format!("{risk:?}")), 1.0),
        (slot("dir", dir), 1.0),
        (slot("ext", ext), 1.0),
        (slot("cap-dir", &format!("{capability}\0{dir}")), 1.0),
        (slot("history", ""), history),
    ]
}

/// The fold an answer is held out in. Hashed rather than `i % FOLDS`, so a person who answers in a
/// regular rhythm (no on every tenth request, say) doesn't have all their noes land in one fold, which
/// would turn the held-out scores against the labels.
fn fold_of(i: usize) -> usize {
    let mut z = (i as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    ((z ^ (z >> 31)) % FOLDS as u64) as usize
}

/// FNV-1a into slots 1..DIM; slot 0 is the bias.
fn slot(kind: &str, value: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in kind.bytes().chain([0]).chain(value.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    1 + (h % (DIM as u64 - 1)) as usize
}

fn score(w: &[f64], x: &Features) -> f64 {
    x.iter().map(|&(i, v)| w[i] * v).sum()
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Logistic regression by full-batch gradient descent with an L2 penalty on everything but the bias.
/// Deterministic: the same rows give the same weights.
fn fit(rows: &[&(Features, bool)]) -> Vec<f64> {
    let mut w = vec![0.0; DIM];
    let n = rows.len().max(1) as f64;
    let mut grad = vec![0.0; DIM];
    for _ in 0..EPOCHS {
        grad.iter_mut().for_each(|g| *g = 0.0);
        for (x, yes) in rows {
            let err = sigmoid(score(&w, x)) - f64::from(u8::from(*yes));
            for &(i, v) in x {
                grad[i] += err * v / n;
            }
        }
        for (i, wi) in w.iter_mut().enumerate() {
            let penalty = if i == 0 { 0.0 } else { L2 * *wi };
            *wi -= RATE * (grad[i] + penalty);
        }
    }
    w
}

/// Platt scaling: fits P(yes) = sigmoid(a * s + b) to the held-out scores, against Platt's smoothed
/// targets (yes + 1) / (yes + 2) and 1 / (no + 2). The smoothing keeps a short record of all yeses
/// below certainty: 40 yeses in a row reach 41/42, under [`THRESHOLD`].
fn platt(scores: &[f64], labels: &[bool]) -> (f64, f64) {
    let yes = labels.iter().filter(|&&y| y).count() as f64;
    let no = labels.len() as f64 - yes;
    let hi = (yes + 1.0) / (yes + 2.0);
    let lo = 1.0 / (no + 2.0);
    let n = scores.len().max(1) as f64;
    let mean_sq = scores.iter().map(|s| s * s).sum::<f64>() / n;
    // A step under 1 / L for this loss, whose gradient is 0.25 * (1 + E[s^2])-Lipschitz at most.
    let step = 4.0 / (1.0 + mean_sq);
    let (mut a, mut b) = (1.0, 0.0);
    for _ in 0..PLATT_EPOCHS {
        let (mut ga, mut gb) = (0.0, 0.0);
        for (&s, &y) in scores.iter().zip(labels) {
            let err = sigmoid(a * s + b) - if y { hi } else { lo };
            ga += err * s / n;
            gb += err / n;
        }
        a -= step * ga;
        b -= step * gb;
    }
    (a, b)
}
