# Changelog

All notable changes to Mohar are written here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may change the
receipt format; each such change is called out.

## [Unreleased]

### Added

- A capability policy (`.mohar/policy.json`): named capabilities with a risk tier, a reversibility flag
  and a ceiling, and ordered rules mapping a host tool and a path or command glob onto them. The first
  match wins; anything unmatched or outside the project root is `unclassified` and treated as the
  highest risk. Invalid files are refused with the reason. The daemon now classifies every action
  itself, so a decide request no longer carries a capability (#47).
- `mohar daemon`: a local service on a loopback address that answers `POST /v1/decide` and
  `POST /v1/outcome`, signs every answer into the log, refuses malformed or oversized requests, answers 503
  past a limit of requests in flight, and rebuilds decisions still waiting for an outcome after a crash (#43).
- `mohar hook claude-code` and a Claude Code plugin in `integrations/claude-code`: every tool call asks the
  daemon first and is allowed, sent to the person, or denied; the hook denies when the daemon is unreachable
  and only talks to loopback addresses. Until the trust engine ships, reads run and everything else asks (#44).
- Receipts can carry an optional `verification` object recording the outcome of an earlier decision.
  Receipts without it are byte-for-byte unchanged.
- Fuzz targets for receipt parsing and verification, checkpoint parsing, the log file readers, and a
  mutation check that any edited log which still parses fails verification. They run for 60 seconds on
  pull requests that touch `crates/` or `fuzz/`, and for 15 minutes each week (#58).
- A log can only be opened for writing by one process at a time; a second writer gets a clear error
  instead of interleaving receipts. Reading and verifying never need the lock (#40).

### Changed

- Verifying a log of a million receipts now takes about 8 seconds instead of about 15.5 on a 6-core
  laptop. Receipts are parsed, canonicalised, hashed and signature-checked on a worker pool that lives
  for the whole walk, and canonical JSON is written by a fixed template that tests compare against
  `serde_jcs` on arbitrary receipts. Every check and every error is unchanged (#59).
- New mark: मो in Modi script on a gold octagonal seal, used for the favicon, the site header, the docs site, the
  README and link previews. The site gains a web manifest and a social preview image.
- The home page is rebuilt as a board of filled tiles with no photographs: a terminal fragment and two
  figures, the simulator with a departure-board receipt log, the four steps as one bar sized by how long each
  takes, receipt fields, trust levels, integrations and a closing action row.
- The hero stamp is a modelled object: a turned rosewood handle with carved vine bands and an engraved brass
  die, built by tools/stamp/build_stamp.py in Blender and loaded as a 1.5 MB Draco-compressed glTF.
- Verifying and opening a log now read `receipts.jsonl` line by line and check checkpoints as the
  receipts go past, so memory use no longer grows with the size of the log. A new `ChainVerifier` checks
  one receipt at a time, `store::verify_file` and `store::verify_log` use it, and signatures are checked
  on all available cores. `mohar verify` and `mohar log` stream too; `log --last N` keeps only N
  receipts. `verify` and `verify_checkpoints` work as before (#59).
- The website scales its type and spacing down to phones, has one header with a menu on every page,
  and uses one button system. A test fails if any page scrolls sideways at 320px (#78).

### Fixed

- The simulator's trust meters showed full at every level in production, because the CSP blocked the inline
  width they were drawn with. The test server now sends the production headers, so tests run under the real CSP.

### Security

- Signatures and public keys must be lowercase hex. Uppercase spellings were accepted, so the last
  receipt in a log could be rewritten without failing verification. Found by the new fuzz targets (#58).

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
