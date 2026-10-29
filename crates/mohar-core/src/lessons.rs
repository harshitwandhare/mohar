//! Lessons after a failure (docs/design.md section 4): what went wrong on a capability and the fix
//! that passed, signed with the log's key and handed back to the agent as context the next time it
//! works on that capability.
//!
//! A lesson is data the agent reads. Nothing here touches the trust ledger, so no lesson can move a
//! gate or a level. After a serious (S3 or S4) failure the agent's earlier lessons are quarantined
//! until a person releases them, since a mistake can come from bad memory as easily as from a bad step.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::{Error, SigningKey, VERSION, VerifyingKey, hex, unhex};

const SIG_PREFIX: &str = "ed25519:";

/// One lesson, as stored and signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lesson {
    /// Format version.
    pub v: u32,
    /// The agent that failed.
    pub agent: String,
    /// The capability it failed on.
    pub capability: String,
    /// When the failure was verified, in seconds since the Unix epoch.
    pub at: u64,
    /// Hash of the receipt recording the failed outcome.
    pub failure: String,
    /// What the verifier found.
    pub finding: String,
    /// Hash of the receipt for the pass that fixed it, or empty while there is none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fix: String,
    /// Hashes of every receipt involved.
    pub receipts: Vec<String>,
    /// Ed25519 signature over the canonical bytes without this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

/// Why a lesson wasn't taken into the book.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LessonError {
    /// Its signature doesn't match its content and the log's key, or its version is unknown.
    #[error("lesson signature does not verify")]
    BadSignature,
}

fn signing_bytes(l: &Lesson) -> Result<Vec<u8>, Error> {
    let mut unsigned = l.clone();
    unsigned.sig.clear();
    serde_jcs::to_vec(&unsigned).map_err(|e| Error::Canonical(e.to_string()))
}

/// Sign `lesson` with the log's key, replacing any signature it had.
pub fn sign(key: &SigningKey, mut lesson: Lesson) -> Result<Lesson, Error> {
    lesson.sig.clear();
    let sig = key.0.sign(&signing_bytes(&lesson)?);
    lesson.sig = format!("{SIG_PREFIX}{}", hex(&sig.to_bytes()));
    Ok(lesson)
}

/// Whether `lesson` is a current-version lesson signed by `key`.
pub fn signature_ok(lesson: &Lesson, key: &VerifyingKey) -> bool {
    if lesson.v != VERSION {
        return false;
    }
    let Some(raw) = lesson.sig.strip_prefix(SIG_PREFIX).and_then(unhex) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    // Encoding a lesson has no failing input today; if one appears, the signature can't be checked.
    let Ok(msg) = signing_bytes(lesson) else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&bytes)).is_ok()
}

/// Every lesson for one log, with the team promotions and quarantines a person has made.
#[derive(Debug, Clone)]
pub struct Book {
    key: VerifyingKey,
    lessons: Vec<Lesson>,
    team: BTreeSet<usize>,
    /// Per agent, the time up to which its lessons are withheld.
    quarantine: BTreeMap<String, u64>,
}

impl Book {
    /// An empty book that accepts lessons signed by `key`.
    pub fn new(key: VerifyingKey) -> Self {
        Self {
            key,
            lessons: Vec::new(),
            team: BTreeSet::new(),
            quarantine: BTreeMap::new(),
        }
    }

    /// Take in a signed lesson. Returns its id, for [`Book::promote`].
    pub fn add(&mut self, lesson: Lesson) -> Result<usize, LessonError> {
        if !signature_ok(&lesson, &self.key) {
            return Err(LessonError::BadSignature);
        }
        self.lessons.push(lesson);
        Ok(self.lessons.len() - 1)
    }

    /// A person promotes a lesson to the team: every agent on its capability gets it. Returns false
    /// if there is no such lesson.
    pub fn promote(&mut self, id: usize) -> bool {
        if id >= self.lessons.len() {
            return false;
        }
        self.team.insert(id);
        true
    }

    /// After a serious failure at `at`, withhold every lesson `agent` built up until then, its team
    /// lessons included, until [`Book::release`]. A later failure widens the window; an earlier one
    /// never narrows it.
    pub fn quarantine(&mut self, agent: &str, at: u64) {
        let until = self.quarantine.entry(agent.to_string()).or_insert(at);
        *until = (*until).max(at);
    }

    /// A person has looked at the quarantined lessons and lets them through again.
    pub fn release(&mut self, agent: &str) {
        self.quarantine.remove(agent);
    }

    /// Whether `agent`'s earlier lessons are withheld.
    pub fn is_quarantined(&self, agent: &str) -> bool {
        self.quarantine.contains_key(agent)
    }

    fn withheld(&self, l: &Lesson) -> bool {
        self.quarantine
            .get(&l.agent)
            .is_some_and(|until| l.at <= *until)
    }

    /// The lessons to hand `agent` as context on `capability`, oldest first: its own and the team's,
    /// leaving out anything quarantined.
    pub fn for_context(&self, agent: &str, capability: &str) -> Vec<&Lesson> {
        self.lessons
            .iter()
            .enumerate()
            .filter(|(id, l)| {
                l.capability == capability
                    && (l.agent == agent || self.team.contains(id))
                    && !self.withheld(l)
            })
            .map(|(_, l)| l)
            .collect()
    }
}
