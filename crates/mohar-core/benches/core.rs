//! The hot paths with targets in docs/engineering-bar.md: appending a receipt and syncing it to disk,
//! verifying receipts, and signing a checkpoint. CI compares these against main on every pull request.
#![allow(clippy::expect_used, missing_docs)]

use std::fs;
use std::path::PathBuf;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mohar_core::store::{FileLog, SignatureChecks, verify_file, verify_log_with};
use mohar_core::{Action, Decision, Entry, parse_public_key};

/// Receipts in the log that the verify benchmark reads, per iteration.
const VERIFY_RECEIPTS: u64 = 1_000;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-bench-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn entry(i: u64) -> Entry {
    Entry {
        ts: "2026-10-14T14:22:07.000Z".into(),
        agent_id: "agent:bench/7c1e".into(),
        action: Action {
            capability: "fs.edit.docs".into(),
            tool: "Edit".into(),
            target: format!("docs/{i}.md"),
            args_sha256: "c41b77d0".into(),
        },
        decision: Decision {
            result: "allow".into(),
            level: 1,
            by: "score".into(),
            review: false,
        },
        verification: None,
    }
}

fn append_and_sync(c: &mut Criterion) {
    let dir = temp_dir("append");
    let mut log = FileLog::init(&dir).expect("init");
    let mut i = 0;
    c.bench_function("append_and_sync", |b| {
        b.iter(|| {
            i += 1;
            log.append(entry(i)).expect("append")
        });
    });
    drop(log);
    let _ = fs::remove_dir_all(&dir);
}

fn verify(c: &mut Criterion) {
    let dir = temp_dir("verify");
    let mut log = FileLog::init(&dir).expect("init");
    for i in 0..VERIFY_RECEIPTS {
        log.append(entry(i)).expect("append");
    }
    drop(log);
    let key = parse_public_key(&fs::read_to_string(dir.join("public.key")).expect("key"))
        .expect("public key");
    let receipts = dir.join("receipts.jsonl");
    let mut group = c.benchmark_group("verify");
    group.throughput(Throughput::Elements(VERIFY_RECEIPTS));
    group.bench_function("1000_receipts", |b| {
        b.iter(|| verify_file(&receipts, &key).expect("verifies"));
    });
    // The same log with a checkpoint over all of it: signatures are skipped, hashes and links kept.
    let mut log = FileLog::open(&dir).expect("reopen");
    log.checkpoint("2026-10-14T15:00:00.000Z")
        .expect("checkpoint");
    drop(log);
    let checkpoints = dir.join("checkpoints.jsonl");
    group.bench_function("1000_receipts_trusting_checkpoint", |b| {
        b.iter(|| {
            verify_log_with(
                &receipts,
                &checkpoints,
                &[],
                &key,
                SignatureChecks::AfterLastCheckpoint,
            )
            .expect("verifies")
        });
    });
    group.finish();
    let _ = fs::remove_dir_all(&dir);
}

fn checkpoint(c: &mut Criterion) {
    let dir = temp_dir("checkpoint");
    let mut log = FileLog::init(&dir).expect("init");
    log.append(entry(0)).expect("append");
    // Signing plus the synced write to checkpoints.jsonl, as `mohar checkpoint` does it.
    c.bench_function("checkpoint_sign_and_sync", |b| {
        b.iter(|| {
            log.checkpoint("2026-10-14T15:00:00.000Z")
                .expect("checkpoint")
        });
    });
    drop(log);
    let _ = fs::remove_dir_all(&dir);
}

criterion_group!(benches, append_and_sync, verify, checkpoint);
criterion_main!(benches);
