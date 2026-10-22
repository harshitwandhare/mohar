#![no_main]
#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use mohar_core::{Receipt, canonical_bytes, receipt_hash, verify};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = serde_json::from_slice::<Receipt>(data) {
        let _ = receipt_hash(&r);
        let _ = canonical_bytes(&r);
        let _ = verify(&[r], &common::public());
    }
});
