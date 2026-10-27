# Changelog

All notable changes to Mohar are written here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may change the
receipt format; each such change is called out.

## [Unreleased]

### Fixed

- A shell redirection is now a write to its target. Before, `cat a > src/main.rs` matched the read-only
  `cat *` rule and never reached the path rules or the protected-path gate; now the write is classified
  and gated like an edit, and a target only the shell can resolve is refused (#131).

## [0.2.0] - 2026-10-26

### Added

- The trust engine guards against rubber-stamping: a human accept counts toward promotion only after 30
  seconds of review, and a reviewer who approves more than 95% of their last 50 reviews stops counting
  until a sampled re-check passes. Rejects always count; tests and diffs are untouched (#50).
- `mohar init --strict-privacy` keeps agent ids and targets out of the log in the clear: each is stored
  as an HMAC-SHA-256 pseudonym under a per-log secret, and the mapping back lives in `identities.jsonl`
  outside the chain, where deleting a line erases someone without breaking verification (#64).
- `mohar daemon --otlp-endpoint <url>` exports OpenTelemetry to a collector on the same machine: a span per
  decision, decisions by result, verifier outcomes, a decision latency histogram and requests in flight,
  over OTLP/HTTP JSON with no new dependencies. Off by default; loopback only (#62).
- Checkpoints can be published to git: `mohar checkpoint --publish git:<clone>` pulls, appends, commits
  and pushes, and `mohar verify --checkpoints git:<clone>` pulls before checking. A log cut short together
  with every local copy of its checkpoints still fails against the remote. Any git step that fails is an
  error, never a silent skip (#108).
- `mohar verify --trust-checkpoints` checks signatures only after the furthest checkpoint whose signature
  verifies, and checks the receipts before it by their hash chain: about five times faster on a covered
  log. The daemon opens its own log this way. Plain `mohar verify` still checks every signature (#117).
- Criterion benchmarks for appending and syncing a receipt, verifying receipts and signing a
  checkpoint, with a CI job that fails a pull request clearly more than 20% slower than main (#60).
- Checkpoints published outside the log directory. `mohar checkpoint --publish <file>` appends the new
  checkpoint to a file that must live outside the log directory, and `mohar verify --checkpoints <file>`
  (repeatable) checks the log against those as well, so a log cut short together with its own
  checkpoints still fails. A named file that can't be read fails verification. Remote targets come
  later (#42).
- The diff verifier: in a git repository, the files a task changed (since its first decision, renames under
  both names, the log directory excluded) must fall under capabilities the agent was given in that task;
  any that don't fail the task with the list returned as `out_of_scope`. It runs before the tests, and each
  decision gets one outcome from the first verifier that fails (#46).
- The tests verifier: when a Claude Code task stops, the daemon runs the project's test command once
  (`verify.tests` in the policy, run with no shell from the root) and records a `tests` outcome for every
  decision in the task that ran and changes something: `pass` on exit 0, `fail` otherwise, `unknown` with
  no command, a command that can't start, or a timeout. An agent that changed a test file in the task
  fails, whatever the tests say. `POST /v1/verify` and the hook's `Stop`/`SubagentStop` handling drive it,
  and a `host` report no longer closes a decision (#45).
- Hard gates in the policy, checked before any trust score: writes outside the project root, denied
  capabilities (the built-in policy denies pushing the default branch), hosts outside an allowlist in a
  fetched URL or a command line, and protected paths (the built-in policy protects `.mohar/`). A gate that
  can't decide refuses. Each stop is a signed `deny` receipt with `by: gate`, and the hook tells the
  person which gate and why (#49).
- The trust engine (`mohar_core::trust`): trust per agent per capability from verified outcomes weighted
  by a 30-day half-life, promotion one level at a time on the 95% Wilson lower bound with minimum counts,
  7 days at a level and 14 quiet days after a serious failure, never above the capability's ceiling.
  Failures are classed S0 to S4: near misses and minor slips change no level, three minor slips in 14
  days count as one meaningful failure, a meaningful failure drops one level, a serious one drops the
  capability and those sharing its scope to Ask first, and an integrity failure suspends the agent until
  a person reinstates it. Demotions start a remediation that blocks promotion until five consecutive
  verified passes. An irreversible high-risk action goes to a person at every level. The daemon decides
  from this ledger and rebuilds it from the signed log on start (#48).
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

- On start the daemon names the decisions still waiting for an outcome (`waiting for an outcome: 2 decisions
  (receipts 1, 5)`) instead of only counting them, and the CLI docs describe its crash safety and overload
  behaviour (#61).
- The CI line coverage floor is 95%, up from 85%. Every line in the daemon, the hook and the core is run by a
  test, apart from branches no input can reach today, which say so beside them (#113, #114).
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

- Shell commands are split into their parts before they are classified and gated. A harmless first
  command used to decide the whole line: with the built-in policy, `ls && git push origin main` was
  read-only and passed the gate that forbids pushing to main. Each part is now classified, the riskiest
  decides, a denied part stops the line, and command substitution, `eval`, `sh -c`, here-documents and
  runtime-built hosts are refused as undecidable (#105).
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

[Unreleased]: https://github.com/harshitwandhare/mohar/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/harshitwandhare/mohar/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/harshitwandhare/mohar/releases/tag/v0.1.0
