//! Strict privacy mode: agent ids and targets kept out of the log in the clear.
//!
//! A log created with [`crate::store::FileLog::init_strict`] holds a second secret, `privacy.key`,
//! beside the signing key. Every agent id and target is written to the chain as
//! `hmac-sha256:<hex>`, the HMAC-SHA-256 of the value under that secret, so the same value always
//! gets the same pseudonym and trust still adds up per agent. The clear value goes only to
//! `identities.jsonl`, which sits outside the chain and can be edited or deleted to erase someone.
//! Verifying the log needs neither file.

use sha2::{Digest, Sha256};

/// What every pseudonym starts with.
pub const PREFIX: &str = "hmac-sha256:";

/// Turns clear values into the pseudonyms one log uses.
pub struct Pseudonyms {
    key: [u8; 32],
}

impl Pseudonyms {
    /// Pseudonyms under a 32-byte secret.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// The pseudonym for `value`. A value that already is a pseudonym is returned as it is, so a
    /// decision read back from the log can be written again without hashing it twice.
    pub fn pseudonym(&self, value: &str) -> String {
        if is_pseudonym(value) {
            return value.to_string();
        }
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(&self.key);
        format!(
            "{PREFIX}{}",
            crate::hex(&hmac_sha256(&block, value.as_bytes()))
        )
    }
}

/// Whether `s` has the exact form of a pseudonym: the prefix and 64 lowercase hex digits.
pub fn is_pseudonym(s: &str) -> bool {
    s.strip_prefix(PREFIX)
        .is_some_and(|h| h.len() == 64 && crate::unhex(h).is_some())
}

/// HMAC-SHA-256 (RFC 2104) with a key already zero-padded to the 64-byte block, which is what HMAC
/// does with any key shorter than the block.
fn hmac_sha256(block: &[u8; 64], msg: &[u8]) -> [u8; 32] {
    let (mut inner_pad, mut outer_pad) = (*block, *block);
    inner_pad.iter_mut().for_each(|b| *b ^= 0x36);
    outer_pad.iter_mut().for_each(|b| *b ^= 0x5c);
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(key: &[u8]) -> [u8; 64] {
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        block
    }

    #[test]
    fn matches_the_rfc_4231_test_vectors() {
        // Test case 1: a 20-byte key of 0x0b.
        assert_eq!(
            crate::hex(&hmac_sha256(&padded(&[0x0b; 20]), b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2: a key shorter than the hash.
        assert_eq!(
            crate::hex(&hmac_sha256(
                &padded(b"Jefe"),
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn the_same_value_gets_the_same_pseudonym_and_another_key_another_one() {
        let a = Pseudonyms::new([1; 32]);
        let b = Pseudonyms::new([2; 32]);
        let p = a.pseudonym("agent:claude-code/docs-writer");
        assert!(is_pseudonym(&p), "{p}");
        assert_eq!(p, a.pseudonym("agent:claude-code/docs-writer"));
        assert_ne!(p, a.pseudonym("agent:claude-code/docs-writer2"));
        assert_ne!(p, b.pseudonym("agent:claude-code/docs-writer"));
    }

    #[test]
    fn a_pseudonym_is_never_hashed_twice() {
        let a = Pseudonyms::new([1; 32]);
        let p = a.pseudonym("docs/a.md");
        assert_eq!(a.pseudonym(&p), p);
    }

    #[test]
    fn only_the_exact_form_counts_as_a_pseudonym() {
        let hex64 = "ab".repeat(32);
        assert!(is_pseudonym(&format!("{PREFIX}{hex64}")));
        for not in [
            String::new(),
            PREFIX.to_string(),
            hex64.clone(),
            format!("{PREFIX}{}", &hex64[..62]),
            format!("{PREFIX}{hex64}00"),
            format!("{PREFIX}{}", hex64.to_uppercase()),
            format!("hmac-sha512:{hex64}"),
        ] {
            assert!(!is_pseudonym(&not), "{not}");
        }
    }
}
