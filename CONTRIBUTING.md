# Contributing

Thanks for wanting to help. This project handles signing and permission decisions, so the bar for
correctness is high, and that applies to everyone.

## How changes land

1. Every change starts from an issue. Comment on it before you start so work isn't duplicated.
2. Branch, make one focused change, and open a pull request that links the issue.
3. CI must be green. A maintainer reviews every pull request; nothing merges unreviewed.

## Sign-off

Commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s
```

If an agent wrote the change, the human who directed it signs off and is responsible for it.

## Local checks

Rust (1.95 or newer), from the repository root:

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Benchmarks, for changes to the receipt log, verification or checkpoints. CI runs them against main on
every pull request and fails when one is clearly more than 20% slower:

```bash
cargo bench -p mohar-core --bench core
```

Fuzzing (nightly toolchain, `cargo install --locked cargo-fuzz`), from the `fuzz` directory:

```bash
cargo +nightly fuzz run chain_mutation -- -max_total_time=60
```

The targets are `receipt_json`, `checkpoint_json`, `log_file` and `chain_mutation`. A crash input lands in
`fuzz/artifacts/`; turn it into a regression test under `crates/mohar-core/tests/` with the fix.

Site (Node 24):

```bash
npm ci
npx playwright install chromium
npx playwright test --project=chromium
```

## Reporting security problems

Don't open a public issue. See [SECURITY.md](https://github.com/harshitwandhare/mohar/blob/main/SECURITY.md).

## Conduct

Everyone here follows the [Code of Conduct](https://github.com/harshitwandhare/mohar/blob/main/CODE_OF_CONDUCT.md). How decisions are made is in
[GOVERNANCE.md](https://github.com/harshitwandhare/mohar/blob/main/GOVERNANCE.md).
