#![no_main]
//! The security property: any edit to a valid log that still parses and changes what it says must
//! fail verification.
#[path = "common.rs"]
mod common;

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use mohar_core::{Receipt, verify};

fn original() -> &'static (Vec<Receipt>, Vec<u8>) {
    static ORIGINAL: OnceLock<(Vec<Receipt>, Vec<u8>)> = OnceLock::new();
    ORIGINAL.get_or_init(|| {
        let receipts = common::log_of(5).receipts().to_vec();
        let mut bytes = Vec::new();
        for r in &receipts {
            if let Ok(line) = serde_json::to_vec(r) {
                bytes.extend_from_slice(&line);
                bytes.push(b'\n');
            }
        }
        (receipts, bytes)
    })
}

fuzz_target!(|edits: &[u8]| {
    let (receipts, base) = original();
    let mut bytes = base.clone();
    // Four bytes per edit: operation, 16-bit position, value.
    for e in edits.chunks_exact(4) {
        if bytes.is_empty() {
            break;
        }
        let pos = ((usize::from(e[1]) << 8) | usize::from(e[2])) % bytes.len();
        match e[0] % 3 {
            0 => bytes[pos] = e[3],
            1 => bytes.insert(pos, e[3]),
            _ => {
                bytes.remove(pos);
            }
        }
    }

    let mut parsed = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Receipt>(line) {
            Ok(r) => parsed.push(r),
            Err(_) => return,
        }
    }
    if &parsed != receipts {
        assert!(
            verify(&parsed, &common::public()).is_err(),
            "an altered log verified"
        );
    }
});
