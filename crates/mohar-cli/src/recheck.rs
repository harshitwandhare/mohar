//! Sampled re-checks of a reviewer's accepts (docs/design.md section 4). A share of each reviewer's
//! passed `human` outcomes is drawn for a second person to look at again, and every accept by a reviewer
//! flagged for rubber-stamping is, so a flag can be cleared. The re-check is its own outcome receipt,
//! `kind` `recheck`, whose `of` is the outcome it checks. Rebuilt from the log on start, the same way the
//! live path builds it, keyed by ids as the log holds them.

use std::collections::HashMap;

use mohar_core::Receipt;
use sha2::{Digest, Sha256};

/// Accepts drawn for a re-check, per thousand, for a reviewer who isn't flagged.
pub const PER_MILLE: u64 = 100;

/// Whether the outcome receipt at `seq` is drawn for a re-check. Fixed by the log's seed, so replay
/// draws the same ones, and tagged apart from the review sample so the two draws don't line up.
pub fn drawn(seed: &[u8; 32], seq: u64) -> bool {
    let digest = Sha256::new()
        .chain_update(b"mohar recheck sample v1")
        .chain_update(seed)
        .chain_update(seq.to_be_bytes())
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % 1000 < PER_MILLE
}

/// The accepts waiting for a re-check.
#[derive(Default)]
pub struct Rechecks {
    /// By the seq of the `human` outcome receipt: the receipt itself, whose reviewer is being checked.
    open: HashMap<u64, Receipt>,
}

impl Rechecks {
    /// Keep in step with an outcome receipt. A passed `human` outcome with a reviewer opens a re-check
    /// when it is drawn or its reviewer is flagged (`flagged`, as the ledger stands after counting it).
    /// Returns whether it opened one.
    pub fn on_outcome(&mut self, r: &Receipt, flagged: bool, seed: &[u8; 32]) -> bool {
        let Some(v) = &r.verification else {
            return false;
        };
        let open = v.kind == "human"
            && v.result == "pass"
            && v.reviewer.is_some()
            && (flagged || drawn(seed, r.seq));
        if open {
            self.open.insert(r.seq, r.clone());
        }
        open
    }

    /// The open re-check of the outcome at `seq`, if any.
    pub fn get(&self, seq: u64) -> Option<&Receipt> {
        self.open.get(&seq)
    }

    /// Close the re-check of the outcome at `seq`, returning the outcome it checked.
    pub fn close(&mut self, seq: u64) -> Option<Receipt> {
        self.open.remove(&seq)
    }

    /// Open re-checks, oldest first: the outcome's seq and whose accept it was.
    pub fn list(&self) -> Vec<(u64, &str)> {
        let mut all: Vec<(u64, &str)> = self
            .open
            .iter()
            .filter_map(|(seq, r)| Some((*seq, r.verification.as_ref()?.reviewer.as_deref()?)))
            .collect();
        all.sort_unstable();
        all
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use mohar_core::{Action, Agent, Decision, Verification};

    fn outcome(seq: u64, kind: &str, result: &str, reviewer: Option<&str>) -> Receipt {
        Receipt {
            v: 1,
            seq,
            prev: String::new(),
            ts: "2026-01-01T00:00:00.000Z".into(),
            agent: Agent {
                id: "agent:a".into(),
                key: String::new(),
            },
            action: Action {
                capability: "fs.edit.docs".into(),
                tool: "Edit".into(),
                target: "docs/a.md".into(),
                args_sha256: "00".into(),
            },
            decision: Decision {
                result: "escalate".into(),
                level: 0,
                by: "score".into(),
                review: false,
                to: Vec::new(),
            },
            verification: Some(Verification {
                evidence_sha256: "00".into(),
                kind: kind.into(),
                of: 0,
                result: result.into(),
                review_secs: reviewer.map(|_| 60),
                reviewer: reviewer.map(ToString::to_string),
            }),
            person: None,
            sig: String::new(),
        }
    }

    #[test]
    fn about_one_in_ten_is_drawn_and_the_draw_is_fixed_by_the_seed() {
        let seed = [7u8; 32];
        let n = (0..10_000).filter(|s| drawn(&seed, *s)).count();
        assert!((900..1_100).contains(&n), "{n}");
        assert_eq!(
            (0..64).map(|s| drawn(&seed, s)).collect::<Vec<_>>(),
            (0..64).map(|s| drawn(&seed, s)).collect::<Vec<_>>()
        );
        let other = (0..64).filter(|s| drawn(&seed, *s) != drawn(&[8u8; 32], *s));
        assert!(other.count() > 0, "another log draws others");
    }

    #[test]
    fn only_a_drawn_or_flagged_accept_with_a_reviewer_opens_one() {
        let seed = [7u8; 32];
        let hit = (0..).find(|s| drawn(&seed, *s)).expect("a drawn seq");
        let miss = (0..).find(|s| !drawn(&seed, *s)).expect("an undrawn seq");
        let mut c = Rechecks::default();
        assert!(c.on_outcome(&outcome(hit, "human", "pass", Some("user:r")), false, &seed));
        assert!(!c.on_outcome(
            &outcome(miss, "human", "pass", Some("user:r")),
            false,
            &seed
        ));
        assert!(c.on_outcome(&outcome(miss, "human", "pass", Some("user:r")), true, &seed));
        for r in [
            outcome(hit + 1_000, "human", "fail", Some("user:r")),
            outcome(hit + 2_000, "human", "pass", None),
            outcome(hit + 3_000, "tests", "pass", None),
        ] {
            assert!(!c.on_outcome(&r, true, &seed), "{:?}", r.verification);
        }
        let mut decision = outcome(hit + 4_000, "human", "pass", Some("user:r"));
        decision.verification = None;
        assert!(!c.on_outcome(&decision, true, &seed));
        let mut want = vec![(hit, "user:r"), (miss, "user:r")];
        want.sort_unstable();
        assert_eq!(c.list(), want);
        assert!(c.get(hit).is_some());
        assert_eq!(c.close(hit).map(|r| r.seq), Some(hit));
        assert!(c.close(hit).is_none(), "closed once");
    }
}
