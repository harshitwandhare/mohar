#![no_main]
#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;
use mohar_core::checkpoint::{Checkpoint, verify_checkpoints};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = serde_json::from_slice::<Checkpoint>(data) {
        let log = common::log_of(5);
        let _ = verify_checkpoints(&[c], log.receipts(), &common::public());
    }
});
