//! How much is being asked of each approver in the hour (docs/design.md section 6): the actions that
//! went to each person and the requests held because they had no room. Rebuilt from the log on start,
//! the same way the live path builds it, and keyed by ids as the log holds them.

use std::collections::{BTreeMap, HashMap};

use mohar_core::{Action, Receipt, action_sha256};
use serde_json::json;

use crate::daemon::parse_rfc3339;

const WINDOW_SECS: u64 = 3_600;
/// How far back an agent's usual rate is measured, for flood flags.
const HISTORY_SECS: u64 = 24 * WINDOW_SECS;
/// Fewest requests in the hour before an agent can be flagged, so a quiet agent's second ask isn't a
/// flood.
const FLOOD_MIN: u64 = 5;
/// How many times its usual hourly rate an agent must ask to be flagged.
const FLOOD_TIMES: u64 = 3;

#[derive(Default)]
pub struct Load {
    /// Per person, the distinct actions asked of them in the last day, with when they were first asked
    /// in their hour. The day is kept for flood flags; budgets look only at the hour.
    asked: HashMap<String, Vec<(u64, String)>>,
    /// Per person, when a request was held this hour and which agent sent it.
    held: HashMap<String, Vec<(u64, String)>>,
}

fn live(at: u64, then: u64) -> bool {
    at.saturating_sub(then) < WINDOW_SECS
}

/// What makes two requests the same question to a person: this agent, this exact action.
pub fn question(agent: &str, action: &Action) -> String {
    format!("{agent}\n{}", action_sha256(action))
}

impl Load {
    /// Keep the counts in step with a decision receipt.
    pub fn record(&mut self, r: &Receipt) {
        let at = parse_rfc3339(&r.ts);
        let d = &r.decision;
        if d.result == "escalate" {
            let asked = question(&r.agent.id, &r.action);
            for person in &d.to {
                let list = self.asked.entry(person.clone()).or_default();
                list.retain(|(then, _)| at.saturating_sub(*then) < HISTORY_SECS);
                if !list.iter().any(|(then, q)| live(at, *then) && *q == asked) {
                    list.push((at, asked.clone()));
                }
            }
        } else if d.result == "deny" && d.by == "budget" {
            for person in &d.to {
                let list = self.held.entry(person.clone()).or_default();
                list.retain(|(then, _)| live(at, *then));
                list.push((at, r.agent.id.clone()));
            }
        }
    }

    fn asked(&self, person: &str, at: u64) -> impl Iterator<Item = &(u64, String)> {
        self.asked
            .get(person)
            .into_iter()
            .flatten()
            .filter(move |(then, _)| live(at, *then))
    }

    /// Whether `person` can be asked `question` at `at`: they were asked it already this hour, or they
    /// have been asked fewer than `per_hour` things.
    pub fn has_room(&self, person: &str, per_hour: u32, question: &str, at: u64) -> bool {
        let mut used = 0_u64;
        for (_, q) in self.asked(person, at) {
            if q == question {
                return true;
            }
            used += 1;
        }
        used < u64::from(per_hour)
    }

    /// Seconds until the oldest thing asked of `person` leaves the hour, which is when they next have
    /// room. A person nobody asked has room now, and a request is held only on someone full.
    pub fn retry_after(&self, person: &str, at: u64) -> u64 {
        self.asked(person, at)
            .map(|(then, _)| (then + WINDOW_SECS).saturating_sub(at))
            .min()
            .unwrap_or(0)
    }

    /// Agents whose distinct requests to `person` this hour are at least [`FLOOD_MIN`] and at least
    /// [`FLOOD_TIMES`] times their usual hourly rate to them over the previous 23 hours. An agent with no
    /// history has a usual rate of 0, so its fifth request in an hour flags it.
    pub fn flooding(&self, person: &str, at: u64) -> Vec<String> {
        let mut counts: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
        for (then, q) in self.asked.get(person).into_iter().flatten() {
            let age = at.saturating_sub(*then);
            if age >= HISTORY_SECS {
                continue;
            }
            let agent = q.split('\n').next().unwrap_or_default();
            let c = counts.entry(agent).or_default();
            if age < WINDOW_SECS {
                c.0 += 1;
            } else {
                c.1 += 1;
            }
        }
        // now >= TIMES * (before / 23 hours), in integers.
        counts
            .into_iter()
            .filter(|(_, (now, before))| {
                *now >= FLOOD_MIN && now * (HISTORY_SECS / WINDOW_SECS - 1) >= FLOOD_TIMES * before
            })
            .map(|(agent, _)| agent.to_string())
            .collect()
    }

    /// What one person's budget looks like at `at`.
    pub fn report(&self, person: &str, per_hour: u32, at: u64) -> serde_json::Value {
        let mut agents: BTreeMap<&str, u64> = BTreeMap::new();
        let mut held = 0_u64;
        for (then, agent) in self.held.get(person).into_iter().flatten() {
            if live(at, *then) {
                held += 1;
                *agents.entry(agent).or_default() += 1;
            }
        }
        json!({
            "per_hour": per_hour,
            "asked": self.asked(person, at).count(),
            "held": held,
            "agents": agents,
            "flooding": self.flooding(person, at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mohar_core::{Agent, Decision};

    const HOUR_START: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z

    fn receipt(secs: u64, result: &str, by: &str, to: &[&str], target: &str) -> Receipt {
        let (m, s) = (secs / 60, secs % 60);
        let (h, m) = (m / 60, m % 60);
        Receipt {
            v: 1,
            seq: 0,
            prev: String::new(),
            ts: format!("2026-01-01T{h:02}:{m:02}:{s:02}.000Z"),
            agent: Agent {
                id: "agent:a".into(),
                key: String::new(),
            },
            action: Action {
                capability: "fs.edit.docs".into(),
                tool: "Edit".into(),
                target: target.into(),
                args_sha256: "00".into(),
            },
            decision: Decision {
                result: result.into(),
                level: 0,
                by: by.into(),
                review: false,
                to: to.iter().map(ToString::to_string).collect(),
            },
            verification: None,
            person: None,
            sig: String::new(),
        }
    }

    fn escalate(secs: u64, target: &str) -> Receipt {
        receipt(secs, "escalate", "score", &["p"], target)
    }

    #[test]
    fn the_budget_is_a_sliding_hour() {
        let mut l = Load::default();
        l.record(&escalate(0, "a"));
        l.record(&escalate(600, "b"));
        let q = "a new question";
        let at = |secs| HOUR_START + secs;
        assert!(
            !l.has_room("p", 2, q, at(3_599)),
            "both are still in the hour"
        );
        assert_eq!(l.retry_after("p", at(3_599)), 1);
        assert!(
            l.has_room("p", 2, q, at(3_600)),
            "the oldest left at exactly an hour"
        );
        assert_eq!(
            l.retry_after("p", at(3_600)),
            600,
            "the next one leaves later"
        );
        assert!(l.has_room("p", 3, q, at(600)), "under the limit");
        assert!(
            !l.has_room("p", 1, q, at(3_600)),
            "one is still in the hour"
        );
        assert_eq!(l.retry_after("nobody", at(0)), 0);
        assert!(l.has_room("nobody", 1, q, at(0)));
    }

    #[test]
    fn asking_the_same_question_again_is_free_until_the_hour_is_up() {
        let mut l = Load::default();
        let r = escalate(0, "a");
        let q = question(&r.agent.id, &r.action);
        l.record(&r);
        l.record(&escalate(60, "a"));
        assert_eq!(
            l.report("p", 1, HOUR_START + 60)["asked"],
            1,
            "one question"
        );
        assert!(l.has_room("p", 1, &q, HOUR_START + 60));
        assert!(!l.has_room("p", 1, "another", HOUR_START + 60));
        // The hour runs from when it was first asked.
        assert!(l.has_room("p", 1, "another", HOUR_START + 3_600));
        // A different agent with the same action is a different question.
        let mut other = escalate(120, "a");
        other.agent.id = "agent:b".into();
        l.record(&other);
        assert_eq!(l.report("p", 2, HOUR_START + 120)["asked"], 2);
    }

    #[test]
    fn old_entries_are_dropped_as_new_ones_come() {
        let mut l = Load::default();
        l.record(&escalate(0, "a"));
        l.record(&escalate(86_400, "b"));
        assert_eq!(l.asked["p"].len(), 1, "a day is kept for flood flags");
        l.record(&receipt(0, "deny", "budget", &["p"], "c"));
        l.record(&receipt(3_600, "deny", "budget", &["p"], "c"));
        assert_eq!(l.held["p"].len(), 1);
    }

    #[test]
    fn only_escalations_and_holds_count() {
        let mut l = Load::default();
        l.record(&receipt(0, "deny", "gate", &["p"], "a"));
        l.record(&receipt(0, "allow", "predicted", &["p"], "a"));
        assert_eq!(
            l.report("p", 3, HOUR_START),
            json!({"per_hour": 3, "asked": 0, "held": 0, "agents": {}, "flooding": []})
        );
    }

    #[test]
    fn the_report_counts_only_this_hour_and_names_the_agents_held() {
        let mut l = Load::default();
        let mut other = receipt(600, "deny", "budget", &["p"], "c");
        other.agent.id = "agent:b".into();
        l.record(&receipt(0, "deny", "budget", &["p"], "c"));
        l.record(&other);
        l.record(&other);
        let want = |held, a: u64, b: u64| {
            let mut agents = serde_json::Map::new();
            if a > 0 {
                agents.insert("agent:a".into(), a.into());
            }
            agents.insert("agent:b".into(), b.into());
            json!({"per_hour": 1, "asked": 0, "held": held, "agents": agents, "flooding": []})
        };
        assert_eq!(l.report("p", 1, HOUR_START + 700), want(3, 1, 2));
        assert_eq!(l.report("p", 1, HOUR_START + 3_600), want(2, 0, 2));
    }

    fn asks(l: &mut Load, agent: &str, from: u64, n: u64, every: u64) {
        for i in 0..n {
            let mut r = escalate(from + i * every, &format!("{agent}-{from}-{i}"));
            r.agent.id = agent.into();
            l.record(&r);
        }
    }

    #[test]
    fn a_question_asked_again_after_its_hour_counts_again() {
        let mut l = Load::default();
        l.record(&escalate(0, "a"));
        l.record(&escalate(3_600, "a"));
        assert_eq!(l.report("p", 1, HOUR_START + 3_600)["asked"], 1);
        assert_eq!(l.asked["p"].len(), 2);
    }

    #[test]
    fn an_agent_with_no_history_is_flagged_at_its_fifth_request_in_the_hour() {
        let mut l = Load::default();
        asks(&mut l, "agent:a", 82_800, 4, 60);
        let at = HOUR_START + 82_800 + 300;
        assert!(l.flooding("p", at).is_empty(), "four is not a flood");
        asks(&mut l, "agent:a", 83_100, 1, 60);
        assert_eq!(l.flooding("p", at), vec!["agent:a".to_string()]);
        assert_eq!(l.report("p", 9, at)["flooding"], json!(["agent:a"]));
        assert!(l.flooding("other", at).is_empty());
    }

    #[test]
    fn a_flood_is_measured_against_the_agent_s_own_usual_rate() {
        // 23 hours at 2 an hour is a usual rate of 2: 6 in the hour is three times it, 5 is not.
        let at = HOUR_START + 86_000;
        let mut l = Load::default();
        asks(&mut l, "agent:a", 0, 46, 1_800);
        asks(&mut l, "agent:a", 82_800, 5, 60);
        assert!(l.flooding("p", at).is_empty(), "5 is under 3 x 2");
        asks(&mut l, "agent:a", 83_200, 1, 60);
        assert_eq!(l.flooding("p", at), vec!["agent:a".to_string()]);
        // Another agent's history doesn't lower this one's bar.
        asks(&mut l, "agent:b", 82_900, 5, 60);
        assert_eq!(
            l.flooding("p", at),
            vec!["agent:a".to_string(), "agent:b".to_string()]
        );
        // Requests older than a day are forgotten.
        assert!(l.flooding("p", at + 86_400).is_empty());
    }

    #[test]
    fn history_more_than_a_day_old_doesn_t_raise_the_bar() {
        // 40 requests just over a day before the question would make 5 normal; they no longer count.
        let mut l = Load::default();
        asks(&mut l, "agent:a", 0, 40, 60);
        asks(&mut l, "agent:a", 85_300, 5, 60);
        assert_eq!(
            l.flooding("p", HOUR_START + 88_800),
            vec!["agent:a".to_string()]
        );
    }
}
