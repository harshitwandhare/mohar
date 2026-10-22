# Changelog

All notable changes to Mohar are written here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may change the
receipt format; each such change is called out.

## [Unreleased]

### Added

- A log can only be opened for writing by one process at a time; a second writer gets a clear error
  instead of interleaving receipts. Reading and verifying never need the lock (#40).

## [0.1.0] - 2026-10-22

The first release: a signed, hash-chained receipt log and the `mohar` command line tool.

### Added

- Receipts: each decision about an agent action is a JSON record signed with Ed25519 over its RFC 8785
  canonical form, and linked to the previous receipt by SHA-256. `verify` reports the first receipt that
  was edited, removed or reordered, and why (#15).
- A log on disk: a directory with the signing key (owner-only on Unix), the public key and
  `receipts.jsonl`. Every receipt is synced before `append` returns, and a log that doesn't verify, or
  whose last line was cut short, is refused rather than extended (#23).
- Signed checkpoints, written every 1,000 receipts and on request, so receipts removed from the end of a
  log are detected (#25).
- The `mohar` CLI: `init`, `append`, `log`, `checkpoint` and `verify`. `verify` needs only the public
  key, so a log can be checked by someone who can't sign (#23, #25).
- Test vectors for the receipt and checkpoint formats, with an independent Python checker that shares no
  code with the Rust implementation (#27).
- Documentation: design (trust levels, verifiers, escalation, receipts, privacy, threat model),
  integrations, compliance with US and EU rules, and how the project sustains itself.

### Security

- CI on Linux, macOS and Windows; CodeQL, OpenSSF Scorecard, gitleaks, cargo-deny, zizmor and an 85%
  line-coverage floor on every pull request; branch protection on `main`; release tags limited to
  admins; release artefacts carry GitHub build attestations.

[Unreleased]: https://github.com/harshitwandhare/mohar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/harshitwandhare/mohar/releases/tag/v0.1.0
