//! The daemon's side of predicting a person's answers (docs/design.md section 6): each person's past
//! answers, the model trained on them, how many answers were predicted for them each day, and how often
//! the checks agreed. All of it is rebuilt from the log on start, the same way the live path builds it.
//!
//! Prediction is off in strict privacy mode: the log holds pseudonyms there, and the limits a person
//! set are paths and an id in the clear, so replay couldn't tell which escalations were checks.

use std::collections::{BTreeMap, HashMap};

use mohar_core::policy::Policy;
use mohar_core::predict::{self, Model, Past, Prediction, Request};
use serde_json::json;

const DAY_SECS: u64 = 86_400;

#[derive(Default)]
pub struct Predictions {
    /// Each person's answers to escalations, oldest first.
    answers: HashMap<String, Vec<Past>>,
    /// The model trained on those answers, kept until the person answers again.
    models: HashMap<String, Option<Model>>,
    /// Predicted answers per person and day (days since the epoch, UTC).
    used: HashMap<(String, u64), u32>,
    /// Escalations drawn as checks and not yet answered, by receipt number, with whose they are.
    open_checks: HashMap<u64, String>,
    /// Per person: checks answered, and how many of those the person said yes to, as predicted.
    agreement: BTreeMap<String, (u32, u32)>,
}

/// One escalation the model might answer.
pub struct Ask<'a> {
    /// The person it was routed to, alone.
    pub person: &'a str,
    pub capability: &'a str,
    /// The action's target as the agent sent it.
    pub target: &'a str,
    /// When the decision is made, in seconds since the epoch.
    pub at: u64,
    /// The receipt number the decision will get.
    pub seq: u64,
}

impl Predictions {
    /// Record a person's answer to an escalation of an action on `capability` at `target`.
    pub fn answered(
        &mut self,
        policy: &Policy,
        person: &str,
        capability: &str,
        target: &str,
        yes: bool,
    ) {
        let target = policy.relative_path(target).unwrap_or_default();
        self.answers
            .entry(person.to_string())
            .or_default()
            .push(Past {
                capability: capability.to_string(),
                risk: policy.spec(capability).risk,
                target,
                yes,
            });
        self.models.remove(person);
    }

    /// An escalation closed by `person`'s answer. If it was a check, count whether they agreed.
    pub fn closed(&mut self, seq: u64, yes: bool) {
        if let Some(person) = self.open_checks.remove(&seq) {
            let a = self.agreement.entry(person).or_default();
            a.0 += 1;
            a.1 += u32::from(yes);
        }
    }

    /// A decision the model answered yes to for `person`.
    pub fn predicted(&mut self, person: &str, at: u64) {
        *self
            .used
            .entry((person.to_string(), at / DAY_SECS))
            .or_default() += 1;
    }

    /// An escalation that went to the person as a check.
    pub fn check_opened(&mut self, seq: u64, person: &str) {
        self.open_checks.insert(seq, person.to_string());
    }

    /// Whether the model answers `ask` for the person. `cheap_first` skips training a model unless the
    /// decision is drawn as a check, for replay, which only needs to find the checks.
    pub fn predict(
        &mut self,
        policy: &Policy,
        ask: &Ask<'_>,
        seed: &[u8; 32],
        cheap_first: bool,
    ) -> Prediction {
        let limits = policy.predict_limits(ask.person);
        let spec = policy.spec(ask.capability);
        let Some(target) = policy.relative_path(ask.target) else {
            return Prediction::Ask(predict::Why::OutsideLimits);
        };
        let mut req = Request {
            capability: ask.capability,
            spec: &spec,
            target: &target,
            used_today: self
                .used
                .get(&(ask.person.to_string(), ask.at / DAY_SECS))
                .copied()
                .unwrap_or(0),
            // Everything but the model first, so nobody's answers are trained on for nothing.
            p_yes: Some(1.0),
        };
        if let Prediction::Ask(why) = predict::decide(&req, &limits, seed, ask.seq) {
            return Prediction::Ask(why);
        }
        if cheap_first && !predict::drawn_for_check(seed, ask.seq) {
            return Prediction::Ask(predict::Why::Unsure);
        }
        let past = self
            .answers
            .get(ask.person)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let model = self
            .models
            .entry(ask.person.to_string())
            .or_insert_with(|| Model::train(past));
        req.p_yes = model
            .as_ref()
            .map(|m| m.p_yes(past, ask.capability, spec.risk, &target));
        predict::decide(&req, &limits, seed, ask.seq)
    }

    /// Per person: predicted answers today, checks answered and how many agreed.
    pub fn report(&self, now: u64) -> serde_json::Value {
        let mut people = serde_json::Map::new();
        let mut names: Vec<&String> = self.agreement.keys().collect();
        names.extend(self.used.keys().map(|(p, _)| p));
        names.extend(self.answers.keys());
        names.sort();
        names.dedup();
        for p in names {
            let (checks, agreed) = self.agreement.get(p).copied().unwrap_or_default();
            let today = self
                .used
                .get(&(p.clone(), now / DAY_SECS))
                .copied()
                .unwrap_or(0);
            people.insert(
                p.clone(),
                json!({"predicted_today": today, "checks": checks, "agreed": agreed}),
            );
        }
        json!({ "people": people })
    }
}
