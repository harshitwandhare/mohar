//! How far up the chain each unanswered question has gone (docs/design.md section 6). Built from the
//! receipts as written, the same way live and on replay, so a restart keeps a question's place. It
//! moves only when the agent asks again; nothing here runs on a timer.

use std::collections::HashMap;

use mohar_core::Receipt;

use crate::daemon::parse_rfc3339;
use crate::load::question;

/// Who has a question now, as the log writes their ids, and since when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk {
    to: Vec<String>,
    since: u64,
}

/// The open walks, by question (agent and action).
#[derive(Default)]
pub struct Walks {
    open: HashMap<String, Walk>,
}

impl Walks {
    /// The walk for `question`, if it is open.
    pub fn get(&self, question: &str) -> Option<&Walk> {
        self.open.get(question)
    }

    /// Keep the walks in step with a decision receipt. Asking the same level again leaves the clock
    /// alone, so an agent that keeps asking can't keep the question with someone who isn't answering.
    pub fn record(&mut self, r: &Receipt) {
        let d = &r.decision;
        let key = question(&r.agent.id, &r.action);
        if d.result == "deny" && d.by == "timeout" {
            self.open.remove(&key);
        } else if d.result == "escalate" && !d.to.is_empty() {
            let same = self.open.get(&key).is_some_and(|w| overlaps(&w.to, &d.to));
            if !same {
                self.open.insert(
                    key,
                    Walk {
                        to: d.to.clone(),
                        since: parse_rfc3339(&r.ts),
                    },
                );
            }
        }
    }

    /// An answer closed the question.
    pub fn close(&mut self, question: &str) {
        self.open.remove(question);
    }
}

/// Budgets can narrow a level to some of its people, so a level is recognised by anyone on it.
fn overlaps(a: &[String], b: &[String]) -> bool {
    a.iter().any(|p| b.contains(p))
}

/// Which level a question goes to at `at`, or `None` when the last one has had its full time. Each move
/// is one level, so everyone on the chain gets the whole timeout however late the agent asks again. A
/// walk matching no level (the policy changed) starts from the first.
pub fn level(walk: Option<&Walk>, levels: &[Vec<String>], at: u64, timeout: u64) -> Option<usize> {
    let Some(w) = walk else { return Some(0) };
    let Some(i) = levels.iter().position(|l| overlaps(l, &w.to)) else {
        return Some(0);
    };
    if at.saturating_sub(w.since) < timeout {
        return Some(i);
    }
    (i + 1 < levels.len()).then_some(i + 1)
}

#[cfg(test)]
mod tests {
    use super::{Walk, level};

    fn levels() -> Vec<Vec<String>> {
        [vec!["a"], vec!["b"], vec!["o1", "o2"]]
            .iter()
            .map(|l| l.iter().map(|p| p.to_string()).collect())
            .collect()
    }

    fn walk(who: &str, since: u64) -> Walk {
        Walk {
            to: vec![who.to_string()],
            since,
        }
    }

    #[test]
    fn a_new_question_goes_to_the_first_level() {
        assert_eq!(level(None, &levels(), 1_000, 60), Some(0));
    }

    #[test]
    fn a_level_keeps_it_for_exactly_the_timeout() {
        let w = walk("a", 1_000);
        assert_eq!(level(Some(&w), &levels(), 1_059, 60), Some(0));
        assert_eq!(level(Some(&w), &levels(), 1_060, 60), Some(1));
    }

    #[test]
    fn a_late_ask_moves_one_level_only() {
        let w = walk("a", 1_000);
        assert_eq!(level(Some(&w), &levels(), 900_000, 60), Some(1));
    }

    #[test]
    fn past_the_last_level_there_is_nobody_left() {
        let w = walk("o2", 1_000);
        assert_eq!(level(Some(&w), &levels(), 1_059, 60), Some(2));
        assert_eq!(level(Some(&w), &levels(), 1_060, 60), None);
        assert_eq!(level(Some(&w), &[], 1_000, 60), Some(0));
    }

    #[test]
    fn a_clock_that_went_backwards_moves_nothing() {
        let w = walk("a", 1_000);
        assert_eq!(level(Some(&w), &levels(), 10, 60), Some(0));
    }

    #[test]
    fn someone_no_longer_on_the_chain_restarts_it() {
        let w = walk("gone", 1_000);
        assert_eq!(level(Some(&w), &levels(), 5_000, 60), Some(0));
    }
}
