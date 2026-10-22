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

Site (Node 24):

```bash
npm ci
npx playwright install chromium
npx playwright test --project=chromium
```

## Reporting security problems

Don't open a public issue. See [SECURITY.md](SECURITY.md).

## Conduct

Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md). How decisions are made is in
[GOVERNANCE.md](GOVERNANCE.md).
