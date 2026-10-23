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
pub mod policy;
pub mod store;
pub mod trust;

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

/// The checked outcome of an earlier decision, carried by a follow-up receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// SHA-256 of the evidence the verifier looked at (a test log, a diff, a review).
    pub evidence_sha256: String,
    /// The verifier: `tests`, `diff`, `replay` or `human`.
    pub kind: String,
    /// `seq` of the decision receipt this outcome belongs to.
    pub of: u64,
    /// `pass`, `fail` or `unknown`.
    pub result: String,
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
    /// Present only on a follow-up receipt that records an outcome. Absent fields leave the bytes of
    /// every earlier receipt unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
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
    /// The outcome this receipt records, if it is a follow-up.
    pub verification: Option<Verification>,
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

/// Strict lowercase hex. A second spelling of the same bytes ("AB", "+f") would give one signed
/// log more than one valid encoding, so only what [`hex`] writes is accepted.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
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
    canonical_with(r, true)
}

/// The bytes that get signed: the canonical receipt with `sig` left out.
fn signing_bytes(r: &Receipt) -> Result<Vec<u8>, Error> {
    canonical_with(r, false)
}

/// Largest integer RFC 8785 writes as plain digits; beyond it the number formatting is subtle, so
/// the general serializer handles those receipts.
const MAX_PLAIN_INT: u64 = 1 << 53;

fn canonical_with(r: &Receipt, with_sig: bool) -> Result<Vec<u8>, Error> {
    if r.seq > MAX_PLAIN_INT
        || r.verification
            .as_ref()
            .is_some_and(|v| v.of > MAX_PLAIN_INT)
    {
        let mut copy = r.clone();
        if !with_sig {
            copy.sig.clear();
        }
        return serde_jcs::to_vec(&copy).map_err(|e| Error::Canonical(e.to_string()));
    }
    Ok(fast_canonical(r, with_sig))
}

/// RFC 8785 for the one shape a receipt has. Every key is ASCII and the keys are written in sorted
/// order, so this is a fixed template; strings are escaped as RFC 8785 requires. Tests compare it with
/// `serde_jcs` on arbitrary receipts.
fn fast_canonical(r: &Receipt, with_sig: bool) -> Vec<u8> {
    use std::io::Write;
    let mut o = Vec::with_capacity(320 + r.sig.len());
    let s = |o: &mut Vec<u8>, key: &str, val: &str| {
        o.extend_from_slice(key.as_bytes());
        json_string(o, val);
    };
    o.extend_from_slice(br#"{"action":{"#);
    s(&mut o, r#""args_sha256":"#, &r.action.args_sha256);
    s(&mut o, r#","capability":"#, &r.action.capability);
    s(&mut o, r#","target":"#, &r.action.target);
    s(&mut o, r#","tool":"#, &r.action.tool);
    o.extend_from_slice(br#"},"agent":{"#);
    s(&mut o, r#""id":"#, &r.agent.id);
    s(&mut o, r#","key":"#, &r.agent.key);
    o.extend_from_slice(br#"},"decision":{"#);
    s(&mut o, r#""by":"#, &r.decision.by);
    // Writing to a Vec cannot fail.
    let _ = write!(o, r#","level":{}"#, r.decision.level);
    s(&mut o, r#","result":"#, &r.decision.result);
    o.extend_from_slice(b"},");
    s(&mut o, r#""prev":"#, &r.prev);
    let _ = write!(o, r#","seq":{}"#, r.seq);
    if with_sig && !r.sig.is_empty() {
        s(&mut o, r#","sig":"#, &r.sig);
    }
    s(&mut o, r#","ts":"#, &r.ts);
    let _ = write!(o, r#","v":{}"#, r.v);
    // "verification" sorts after "v", so it closes the object when present.
    if let Some(v) = &r.verification {
        s(
            &mut o,
            r#","verification":{"evidence_sha256":"#,
            &v.evidence_sha256,
        );
        s(&mut o, r#","kind":"#, &v.kind);
        let _ = write!(o, r#","of":{}"#, v.of);
        s(&mut o, r#","result":"#, &v.result);
        o.push(b'}');
    }
    o.push(b'}');
    o
}

fn json_string(o: &mut Vec<u8>, s: &str) {
    o.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => br#"\""#,
            b'\\' => br"\\",
            0x08 => br"\b",
            0x09 => br"\t",
            0x0a => br"\n",
            0x0c => br"\f",
            0x0d => br"\r",
            0..=0x1f => {
                o.extend_from_slice(&bytes[start..i]);
                o.extend_from_slice(br"\u00");
                o.push(b"0123456789abcdef"[(b >> 4) as usize]);
                o.push(b"0123456789abcdef"[(b & 0xf) as usize]);
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        o.extend_from_slice(&bytes[start..i]);
        o.extend_from_slice(esc);
        start = i + 1;
    }
    o.extend_from_slice(&bytes[start..]);
    o.push(b'"');
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
        verification: entry.verification,
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
    // Encoding a parsed receipt has no failing input today; if one appears, it doesn't verify.
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
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        Action, Agent, BreakKind, ChainVerifier, Decision, Prechecked, Receipt, SigningKey,
        Verification, canonical, hex, signing_bytes, unhex,
    };
    use proptest::prelude::*;

    /// Strings that reach every escaping branch: control characters, quotes and backslashes mixed
    /// with any other character. proptest's own `String` strategy never makes control characters.
    fn text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                any::<char>(),
                (0u8..0x20).prop_map(char::from),
                Just('"'),
                Just('\\'),
            ],
            0..24,
        )
        .prop_map(String::from_iter)
    }

    fn receipt(
        s: [String; 8],
        (v, seq, level): (u32, u64, u8),
        sig: String,
        verification: Option<Verification>,
    ) -> Receipt {
        let [prev, ts, id, key, capability, tool, target, by] = s;
        Receipt {
            v,
            seq,
            prev,
            ts,
            agent: Agent { id, key },
            action: Action {
                capability,
                tool,
                target,
                args_sha256: by.clone(),
            },
            decision: Decision {
                result: by.clone(),
                level,
                by,
            },
            sig,
            verification,
        }
    }

    proptest! {
        /// The template canonicaliser writes exactly what the general RFC 8785 serializer does, for
        /// any strings (control characters, quotes, backslashes, non-ASCII) and any integers.
        #[test]
        fn fast_canonical_matches_serde_jcs(
            s in proptest::array::uniform8(text()),
            n in (any::<u32>(), any::<u64>(), any::<u8>()),
            sig in prop_oneof![Just(String::new()), text()],
            verification in proptest::option::of((text(), text(), any::<u64>(), text())
                .prop_map(|(evidence_sha256, kind, of, result)| Verification { evidence_sha256, kind, of, result })),
        ) {
            let r = receipt(s, n, sig, verification);
            let general = serde_jcs::to_vec(&r).expect("jcs");
            prop_assert_eq!(canonical(&r).expect("fast"), general);
            let mut unsigned = r.clone();
            unsigned.sig.clear();
            prop_assert_eq!(
                signing_bytes(&r).expect("fast"),
                serde_jcs::to_vec(&unsigned).expect("jcs")
            );
        }
    }

    /// Every ASCII byte that RFC 8785 escapes, plus the ones it leaves alone, in every string field.
    #[test]
    fn every_escaped_character_matches_serde_jcs_in_every_field() {
        let all: String = (0u8..0x80).map(char::from).chain(['é', '😀']).collect();
        for field in 0..8 {
            let mut s: [String; 8] = Default::default();
            s[field] = all.clone();
            let r = receipt(
                s,
                (1, 0, 0),
                all.clone(),
                Some(Verification {
                    evidence_sha256: all.clone(),
                    kind: all.clone(),
                    of: 0,
                    result: all.clone(),
                }),
            );
            assert_eq!(
                canonical(&r).expect("fast"),
                serde_jcs::to_vec(&r).expect("jcs")
            );
        }
    }

    #[test]
    fn a_receipt_whose_hash_could_not_be_computed_breaks_the_chain() {
        let key = SigningKey::generate().expect("key");
        let vk = key.verifying_key();
        let mut log = super::Log::new(key);
        let r = log
            .append(super::Entry {
                ts: "2026-10-14T14:22:07.000Z".into(),
                agent_id: "agent:test/1".into(),
                action: Action {
                    capability: "fs.edit.docs".into(),
                    tool: "Edit".into(),
                    target: "docs/a.md".into(),
                    args_sha256: "c41b77d0".into(),
                },
                decision: Decision {
                    result: "allow".into(),
                    level: 1,
                    by: "score".into(),
                },
                verification: None,
            })
            .expect("append")
            .clone();
        let mut chain = ChainVerifier::new(&vk);
        let unhashable = Prechecked {
            signature_ok: true,
            hash: None,
        };
        let err = chain
            .push_prechecked(&r, unhashable)
            .expect_err("must fail");
        assert_eq!(err.kind, BreakKind::Unreadable);
        assert_eq!(chain.count(), 0);
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let bytes = [0u8, 1, 0x7f, 0xff];
        assert_eq!(hex(&bytes), "00017fff");
        assert_eq!(unhex("00017fff"), Some(bytes.to_vec()));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("AB"), None);
        assert_eq!(unhex("+f"), None);
    }
}
