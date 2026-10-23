//! Signed checkpoints: "the log held `count` receipts and the last one hashed to `head`".
//!
//! A hash chain shows that nothing in the middle changed, but receipts removed from the end leave a
//! shorter chain that still verifies. A checkpoint signed earlier makes that removal visible.

use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::{Error, Receipt, SigningKey, VERSION, VerifyingKey, hex, receipt_hash, unhex};

const SIG_PREFIX: &str = "ed25519:";

/// A signed statement about the log at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Format version.
    pub v: u32,
    /// Number of receipts in the log when this was signed.
    pub count: u64,
    /// Hash of the receipt at index `count - 1`.
    pub head: String,
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Ed25519 signature over the canonical bytes without this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

/// Why a set of checkpoints doesn't match the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointBreak {
    /// The checkpoint's signature doesn't match its content and the key.
    #[error("checkpoint {checkpoint}: bad signature")]
    BadSignature {
        /// Index of the checkpoint.
        checkpoint: usize,
    },
    /// The log has fewer receipts than the checkpoint vouched for.
    #[error("checkpoint {checkpoint}: log should hold {expected} receipts, holds {found}")]
    LogTooShort {
        /// Index of the checkpoint.
        checkpoint: usize,
        /// Receipts the checkpoint vouched for.
        expected: u64,
        /// Receipts actually present.
        found: u64,
    },
    /// The receipt at the checkpoint's position isn't the one it vouched for.
    #[error("checkpoint {checkpoint}: receipt {seq} differs from the one signed for")]
    HeadMismatch {
        /// Index of the checkpoint.
        checkpoint: usize,
        /// Sequence number of the receipt that differs.
        seq: u64,
    },
    /// The checkpoint or a receipt couldn't be canonicalised.
    #[error("checkpoint {checkpoint}: unreadable")]
    Unreadable {
        /// Index of the checkpoint.
        checkpoint: usize,
    },
}

fn signing_bytes(c: &Checkpoint) -> Result<Vec<u8>, Error> {
    let mut unsigned = c.clone();
    unsigned.sig.clear();
    serde_jcs::to_vec(&unsigned).map_err(|e| Error::Canonical(e.to_string()))
}

/// Sign a checkpoint for a log of `count` receipts whose last receipt hashes to `head`.
pub(crate) fn sign(
    key: &SigningKey,
    count: u64,
    head: String,
    ts: String,
) -> Result<Checkpoint, Error> {
    let mut c = Checkpoint {
        v: VERSION,
        count,
        head,
        ts,
        sig: String::new(),
    };
    let sig = key.0.sign(&signing_bytes(&c)?);
    c.sig = format!("{SIG_PREFIX}{}", hex(&sig.to_bytes()));
    Ok(c)
}

fn signature_ok(c: &Checkpoint, key: &VerifyingKey) -> bool {
    let Some(raw) = c.sig.strip_prefix(SIG_PREFIX).and_then(unhex) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    // Encoding a checkpoint has no failing input today; if one appears, the signature can't be checked.
    let Ok(msg) = signing_bytes(c) else {
        return false;
    };
    key.verify(&msg, &Signature::from_bytes(&bytes)).is_ok()
}

/// Check every checkpoint against the receipts. Run [`crate::verify`] on the receipts as well: this
/// only answers whether the log still holds what each checkpoint vouched for.
pub fn verify_checkpoints(
    checkpoints: &[Checkpoint],
    receipts: &[Receipt],
    key: &VerifyingKey,
) -> Result<(), CheckpointBreak> {
    for (checkpoint, c) in checkpoints.iter().enumerate() {
        if c.v != VERSION || !signature_ok(c, key) {
            return Err(CheckpointBreak::BadSignature { checkpoint });
        }
        if c.count == 0 {
            continue;
        }
        let found = receipts.len() as u64;
        if found < c.count {
            return Err(CheckpointBreak::LogTooShort {
                checkpoint,
                expected: c.count,
                found,
            });
        }
        let seq = c.count - 1;
        // The length check above means the receipt is there. Hashing a parsed receipt has no
        // failing input today; if one appears, the checkpoint can't be confirmed and fails.
        match receipts.get(seq as usize).map(receipt_hash) {
            Some(Ok(h)) if h == c.head => {}
            Some(Ok(_)) => return Err(CheckpointBreak::HeadMismatch { checkpoint, seq }),
            _ => return Err(CheckpointBreak::Unreadable { checkpoint }),
        }
    }
    Ok(())
}

/// Checks checkpoints while receipts stream past, so the receipts never have to be held together.
///
/// Only the checkpoints are kept, and there is one per thousand receipts.
pub(crate) struct CheckpointWatcher {
    /// `(position of the vouched-for receipt, checkpoint index, head)`, sorted by position.
    pending: Vec<(u64, usize, String)>,
    cursor: usize,
    first_break: Option<(usize, CheckpointBreak)>,
}

impl CheckpointWatcher {
    /// Check every signature up front, in order, and queue the checkpoints for the stream.
    pub(crate) fn new(
        checkpoints: &[Checkpoint],
        key: &VerifyingKey,
    ) -> Result<Self, CheckpointBreak> {
        let mut pending = Vec::new();
        for (checkpoint, c) in checkpoints.iter().enumerate() {
            if c.v != VERSION || !signature_ok(c, key) {
                return Err(CheckpointBreak::BadSignature { checkpoint });
            }
            if c.count > 0 {
                pending.push((c.count - 1, checkpoint, c.head.clone()));
            }
        }
        pending.sort_by_key(|(seq, checkpoint, _)| (*seq, *checkpoint));
        Ok(Self {
            pending,
            cursor: 0,
            first_break: None,
        })
    }

    /// The receipt at position `seq` has just verified and hashes to `hash`.
    pub(crate) fn observe(&mut self, seq: u64, hash: &str) {
        while let Some((at, checkpoint, head)) = self.pending.get(self.cursor) {
            if *at != seq {
                break;
            }
            let (checkpoint, mismatch) = (*checkpoint, head != hash);
            self.cursor += 1;
            if mismatch {
                self.note(
                    checkpoint,
                    CheckpointBreak::HeadMismatch { checkpoint, seq },
                );
            }
        }
    }

    fn note(&mut self, checkpoint: usize, b: CheckpointBreak) {
        if self.first_break.is_none_or(|(c, _)| checkpoint < c) {
            self.first_break = Some((checkpoint, b));
        }
    }

    /// The stream ended after `found` receipts; whatever is still queued vouched for more than that.
    pub(crate) fn finish(mut self, found: u64) -> Result<(), CheckpointBreak> {
        let rest: Vec<(u64, usize)> = self.pending[self.cursor..]
            .iter()
            .map(|(at, checkpoint, _)| (*at, *checkpoint))
            .collect();
        for (at, checkpoint) in rest {
            self.note(
                checkpoint,
                CheckpointBreak::LogTooShort {
                    checkpoint,
                    expected: at + 1,
                    found,
                },
            );
        }
        self.first_break.map_or(Ok(()), |(_, b)| Err(b))
    }
}
