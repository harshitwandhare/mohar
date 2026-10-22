#![no_main]
#[path = "common.rs"]
mod common;

use std::fs;
use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use mohar_core::checkpoint::verify_checkpoints;
use mohar_core::store::{FileLog, read_checkpoints, read_receipts};
use mohar_core::verify;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("mohar-fuzz-log-{}", std::process::id()));
    let _ = fs::create_dir_all(&d);
    d
}

fuzz_target!(|data: &[u8]| {
    let dir = dir();
    // The first byte decides where the input is split between the two files.
    let (split, rest) = data
        .split_first()
        .map_or((0, data), |(s, r)| (usize::from(*s), r));
    let cut = split.min(rest.len());
    let (log_bytes, cp_bytes) = rest.split_at(cut);
    let log_path = dir.join("receipts.jsonl");
    let cp_path = dir.join("checkpoints.jsonl");
    let key_path = dir.join("key.ed25519");
    if fs::write(&log_path, log_bytes).is_err()
        || fs::write(&cp_path, cp_bytes).is_err()
        || fs::write(&key_path, common::SEED).is_err()
    {
        return;
    }

    let public = common::public();
    let receipts = read_receipts(&log_path);
    let checkpoints = read_checkpoints(&cp_path);
    if let (Ok(r), Ok(c)) = (&receipts, &checkpoints) {
        let _ = verify(r, &public);
        let _ = verify_checkpoints(c, r, &public);
    }
    let _ = FileLog::open(&dir);
});
