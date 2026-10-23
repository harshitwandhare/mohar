# Engineering bar

The standard every part of Mohar is held to. Each line is something CI checks or a test proves; a
change that can't meet a line says so in its pull request and opens a follow-up issue. Numbers are
targets for the first production-ready release and are measured, not assumed.

## Correctness

- Every rule about signing, verification, the log, gates and trust decisions has a test for the failure
  path, and a pull request touching one shows a mutation check: the rule broken on purpose, a test
  failing, the rule restored.
- Property tests for the receipt chain, checkpoints and trust levels (proptest).
- Fuzzing of every parser that reads untrusted input (receipts, checkpoints, policy files, daemon
  requests) with cargo-fuzz, run in CI for a fixed time on every pull request touching them and nightly
  for longer.
- Published test vectors, checked by an independent implementation in CI.
- Line coverage of at least 95%, enforced in CI. A line no test can reach says why beside it.

## Reliability

- Fail closed everywhere: if Mohar can't decide, the action is denied, and adapters on enforcing hosts
  deny when the daemon is unreachable.
- Crash safety: a receipt is on disk before it is acknowledged; a torn last line is detected on open; a
  test kills the daemon between decide and outcome and shows the log still verifies and the pending
  decision is visible after restart.
- One writer per log, enforced by an OS file lock.
- No panics on input: `unwrap` is denied by lint; every error is a typed error with a clear message.
- The daemon degrades predictably: when it is overloaded it refuses new decisions with a clear error
  rather than queueing without bound.

## Performance

Targets on a single core of a mid-range laptop, except verification, which spreads over every core:
one receipt (parsing, hashing and the Ed25519 check) costs about 40 µs of CPU, so a million take
about 38 s on one core and under 10 s on eight threads. CI verifies a million receipts on every pull
request with the budget scaled to the runner's threads. Append, verify and checkpoint signing are measured by
criterion benchmarks (`crates/mohar-core/benches`), and CI fails a pull request that makes one more
than 20% slower than main, judged by the lower end of the confidence interval and confirmed by a
second run. Criterion reports means; the p99 targets still need a latency histogram (the daemon
metrics work).

| Operation | Target |
|---|---|
| Decide (gates plus trust lookup, excluding the hook's own process start) | p99 under 2 ms |
| Append and sync one receipt | p99 under 5 ms on SSD |
| Verify a 1,000,000-receipt chain | under 10 s with 8 hardware threads, constant memory |
| Daemon memory at idle | under 30 MB |

Verification streams the log instead of loading it whole, so log size never limits it.

## Scalability

- One daemon per machine is the unit. Teams scale by running many machines, each with its own log;
  checkpoints from every machine can be published to a shared, append-only store and verified
  independently.
- Logs rotate into segments behind signed checkpoints, so a long-running machine's active file stays
  small and old segments can be archived.
- The receipt format and the decide API are versioned; old receipts stay verifiable forever.

## Security

- Unsafe Rust is forbidden at the workspace level.
- Private keys belong to the daemon's OS user and never leave it; agents never see them.
- Dependencies pass cargo-deny (advisories, licences, sources) on every pull request and weekly.
- Workflows pass zizmor; every action is pinned to a commit; checkouts don't persist credentials.
- Releases carry GitHub build attestations and checksums.
- Vulnerabilities are reported privately and fixed before disclosure (SECURITY.md).

## Observability

- The daemon exports metrics (decisions by result, latency histograms, verifier outcomes, queue depth)
  and traces using OpenTelemetry, off by default and local-only unless configured.
- Every decision is explainable from its receipt alone: which gate or score decided it and the evidence
  behind it.

## Compatibility

- Linux, macOS and Windows on x86_64, plus Linux and macOS on arm64, built and tested in CI.
- Minimum supported Rust version declared in Cargo.toml and tested.
- Semantic versioning. Before 1.0 a minor version may change the receipt format; every such change is
  listed in the changelog with a migration note.
