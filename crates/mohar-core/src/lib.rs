//! Signed, hash-chained receipts for decisions about AI agent actions.
//!
//! Each [`Receipt`] is signed with Ed25519 over its RFC 8785 canonical JSON with `sig` left out, and
//! carries in `prev` the SHA-256 of the previous receipt's full canonical JSON, signature included.
//! Editing, deleting or reordering any receipt therefore breaks verification at a known index.
//! See `docs/design.md`, section 7.

use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod checkpoint;
pub mod store;

pub use ed25519_dalek::VerifyingKey;

/// Receipt format version written into every receipt.
pub const VERSION: u32 = 1;

const SHA_PREFIX: &str = "sha256:";
const SIG_PREFIX: &str = "ed25519:";

/// The action an agent asked to take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// Capability the action falls under, such as `fs.edit.tests`.
    pub capability: String,
    /// Host tool that would run it.
    pub tool: String,
    /// What it acts on: a path, a branch, a host.
    pub target: String,
    /// SHA-256 of the exact arguments; approvals are bound to this.
    pub args_sha256: String,
}

/// What Mohar decided about the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// `allow`, `escalate` or `deny`.
    pub result: String,
    /// The agent's trust level on this capability when the decision was made.
    pub level: u8,
    /// What decided it: `gate`, `score`, `human` or `predicted`.
    pub by: String,
}

/// The agent that acted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// Stable agent identifier.
    pub id: String,
    /// Public key of the daemon that signed this receipt.
    pub key: String,
}

/// One signed entry in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Format version.
    pub v: u32,
    /// Position in the log, starting at 0.
    pub seq: u64,
    /// SHA-256 of the previous receipt's canonical bytes, or zeros for the first.
    pub prev: String,
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Who acted.
    pub agent: Agent,
    /// What it asked to do.
    pub action: Action,
    /// What was decided.
    pub decision: Decision,
    /// Ed25519 signature over the canonical bytes without this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

/// The fields a caller supplies; the log fills in the rest.
#[derive(Debug, Clone)]
pub struct Entry {
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Stable agent identifier.
    pub agent_id: String,
    /// What the agent asked to do.
    pub action: Action,
    /// What was decided.
    pub decision: Decision,
}

/// Errors from building or signing receipts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The receipt couldn't be canonicalised.
    #[error("canonical JSON: {0}")]
    Canonical(String),
    /// The operating system gave no randomness for a new key.
    #[error("randomness unavailable: {0}")]
    Random(String),
}

/// Why verification stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// `seq` isn't the receipt's position in the list.
    WrongSequence,
    /// `prev` doesn't match the hash of the receipt before it.
    BrokenLink,
    /// The signature is missing, malformed, or doesn't match the content and key.
    BadSignature,
    /// The receipt names a format version this code doesn't know.
    UnknownVersion,
    /// The receipt couldn't be canonicalised.
    Unreadable,
}

/// The first place a chain fails to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("receipt {index}: {kind:?}")]
pub struct ChainBreak {
    /// Index in the list that was verified.
    pub index: usize,
    /// What was wrong with it.
    pub kind: BreakKind,
}

/// The daemon's signing key. Agents never hold this.
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// A new key from the operating system's random source.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// Rebuild a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub(crate) fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Lowercase hex, without a dependency for twenty lines of work.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The RFC 8785 canonical bytes of a receipt, signature included: what [`receipt_hash`] hashes.
pub fn canonical_bytes(r: &Receipt) -> Result<Vec<u8>, Error> {
    canonical(r)
}

fn canonical(r: &Receipt) -> Result<Vec<u8>, Error> {
    serde_jcs::to_vec(r).map_err(|e| Error::Canonical(e.to_string()))
}

/// The bytes that get signed: the canonical receipt with `sig` empty, which serde leaves out.
fn signing_bytes(r: &Receipt) -> Result<Vec<u8>, Error> {
    let mut unsigned = r.clone();
    unsigned.sig.clear();
    canonical(&unsigned)
}

/// The hash the next receipt's `prev` must equal: over the full receipt, signature included.
pub fn receipt_hash(r: &Receipt) -> Result<String, Error> {
    Ok(format!(
        "{SHA_PREFIX}{}",
        hex(&Sha256::digest(canonical(r)?))
    ))
}

/// Build and sign the receipt at position `seq` that follows a receipt hashing to `prev`.
pub(crate) fn seal(
    key: &SigningKey,
    seq: u64,
    prev: String,
    entry: Entry,
) -> Result<Receipt, Error> {
    let mut r = Receipt {
        v: VERSION,
        seq,
        prev,
        ts: entry.ts,
        agent: Agent {
            id: entry.agent_id,
            key: public_key_string(&key.verifying_key()),
        },
        action: entry.action,
        decision: entry.decision,
        sig: String::new(),
    };
    let sig = key.0.sign(&signing_bytes(&r)?);
    r.sig = format!("{SIG_PREFIX}{}", hex(&sig.to_bytes()));
    Ok(r)
}

/// A public key as written in receipts and key files: `ed25519:` and 64 hex digits.
pub fn public_key_string(key: &VerifyingKey) -> String {
    format!("{SIG_PREFIX}{}", hex(key.as_bytes()))
}

/// Parse a public key written by [`public_key_string`].
pub fn parse_public_key(s: &str) -> Option<VerifyingKey> {
    let raw = unhex(s.trim().strip_prefix(SIG_PREFIX)?)?;
    VerifyingKey::from_bytes(&<[u8; 32]>::try_from(raw.as_slice()).ok()?).ok()
}

pub(crate) fn genesis() -> String {
    format!("{SHA_PREFIX}{}", "0".repeat(64))
}

/// An append-only, in-memory receipt log. Persistence comes later; the chain rules live here.
pub struct Log {
    key: SigningKey,
    receipts: Vec<Receipt>,
}

impl Log {
    /// An empty log that will sign with `key`.
    pub fn new(key: SigningKey) -> Self {
        Self {
            key,
            receipts: Vec::new(),
        }
    }

    /// Sign and append a receipt for `entry`, returning it.
    pub fn append(&mut self, entry: Entry) -> Result<&Receipt, Error> {
        let prev = match self.receipts.last() {
            Some(last) => receipt_hash(last)?,
            None => genesis(),
        };
        let r = seal(&self.key, self.receipts.len() as u64, prev, entry)?;
        self.receipts.push(r);
        Ok(self
            .receipts
            .last()
            .unwrap_or_else(|| unreachable!("just pushed")))
    }

    /// Sign a checkpoint over the log as it stands.
    pub fn checkpoint(&self, ts: &str) -> Result<checkpoint::Checkpoint, Error> {
        let head = match self.receipts.last() {
            Some(last) => receipt_hash(last)?,
            None => genesis(),
        };
        checkpoint::sign(&self.key, self.receipts.len() as u64, head, ts.to_string())
    }

    /// All receipts, oldest first.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
}

fn check_signature(r: &Receipt, key: &VerifyingKey) -> bool {
    let Some(raw) = r.sig.strip_prefix(SIG_PREFIX).and_then(unhex) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    let Ok(msg) = signing_bytes(r) else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&bytes)).is_ok()
}

/// What can be worked out about a receipt without knowing where it sits in the chain.
pub(crate) struct Prechecked {
    signature_ok: bool,
    hash: Option<String>,
}

impl Prechecked {
    pub(crate) fn of(r: &Receipt, key: &VerifyingKey) -> Self {
        Self {
            signature_ok: check_signature(r, key),
            hash: receipt_hash(r).ok(),
        }
    }

    /// The result for a receipt that couldn't be checked at all: it fails closed.
    pub(crate) fn failed() -> Self {
        Self {
            signature_ok: false,
            hash: None,
        }
    }
}

/// Checks a chain one receipt at a time, holding only what the next receipt must match.
///
/// Memory use is the same for a log of ten receipts and a log of ten million: the expected `prev`
/// hash and the next position. [`verify`] and the file readers in [`store`] are built on it.
pub struct ChainVerifier<'k> {
    key: &'k VerifyingKey,
    expected_prev: String,
    next_index: usize,
}

impl<'k> ChainVerifier<'k> {
    /// A verifier at the start of a chain, checking signatures against `key`.
    pub fn new(key: &'k VerifyingKey) -> Self {
        Self {
            key,
            expected_prev: genesis(),
            next_index: 0,
        }
    }

    /// Check the next receipt in the chain. On failure the verifier is left where it was.
    ///
    /// Anything that can't be checked counts as a failure.
    pub fn push(&mut self, r: &Receipt) -> Result<(), ChainBreak> {
        let checked = Prechecked::of(r, self.key);
        self.push_prechecked(r, checked)
    }

    /// [`push`](Self::push) with the expensive, order-independent work (signature and hash) already
    /// done, so a caller can do it for a batch of receipts on several threads. The checks that depend
    /// on position still run here, in the same order as `push`.
    pub(crate) fn push_prechecked(
        &mut self,
        r: &Receipt,
        checked: Prechecked,
    ) -> Result<(), ChainBreak> {
        let index = self.next_index;
        let fail = |kind| Err(ChainBreak { index, kind });
        if r.v != VERSION {
            return fail(BreakKind::UnknownVersion);
        }
        if !checked.signature_ok {
            return fail(BreakKind::BadSignature);
        }
        if r.seq != index as u64 {
            return fail(BreakKind::WrongSequence);
        }
        if r.prev != self.expected_prev {
            return fail(BreakKind::BrokenLink);
        }
        match checked.hash {
            Some(h) => self.expected_prev = h,
            None => return fail(BreakKind::Unreadable),
        }
        self.next_index += 1;
        Ok(())
    }

    /// How many receipts have been accepted so far.
    pub fn count(&self) -> u64 {
        self.next_index as u64
    }

    /// The hash the next receipt's `prev` must equal: that of the last accepted receipt.
    pub fn head(&self) -> &str {
        &self.expected_prev
    }
}

/// Check a whole chain, oldest first, against the daemon's public key.
///
/// Returns the first receipt that fails and why. Anything that can't be checked counts as a failure.
pub fn verify(receipts: &[Receipt], key: &VerifyingKey) -> Result<(), ChainBreak> {
    let mut chain = ChainVerifier::new(key);
    receipts.iter().try_for_each(|r| chain.push(r))
}

#[cfg(test)]
mod tests {
    use super::{hex, unhex};

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0u8, 1, 0x7f, 0xff];
        assert_eq!(hex(&bytes), "00017fff");
        assert_eq!(unhex("00017fff"), Some(bytes.to_vec()));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }
}
