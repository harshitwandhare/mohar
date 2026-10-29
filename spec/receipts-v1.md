# Mohar receipts, format version 1

Spec version 1.1.0

This document describes the receipts and checkpoints Mohar writes, apart from the Rust code, so a
verifier can be written in any language. It covers receipt format `v: 1`. The reference implementation is
`crates/mohar-core` in this repository; [`spec/vectors/check.py`](vectors/check.py) is a second,
independent one in Python. Where this document and either implementation disagree, that is a bug in one
of the three, and the [test vectors](vectors/README.md) decide which.

The key words MUST, MUST NOT, SHOULD and MAY are used as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
when they appear in capitals.

## 1. Encodings

| What | Written as |
|---|---|
| Hash | `sha256:` followed by the 64 lowercase hex digits of a SHA-256 digest |
| Public key | `ed25519:` followed by the 64 lowercase hex digits of a 32-byte Ed25519 public key |
| Signature | `ed25519:` followed by the 128 lowercase hex digits of a 64-byte Ed25519 signature |
| Timestamp | RFC 3339 in UTC, such as `2026-10-14T14:22:07.311Z` |

Hex MUST be lowercase. A verifier MUST treat any other spelling of the same bytes (uppercase digits, a
missing prefix, extra whitespace inside the value) as a failure, so that each receipt has exactly one
encoding and one hash.

## 2. Receipt

A receipt is a JSON object with these keys, and no others:

| Key | Type | Meaning |
|---|---|---|
| `v` | integer | Format version. MUST be `1`. |
| `seq` | integer | Position in the log, starting at 0. |
| `prev` | hash | Hash of the previous receipt (section 4). |
| `ts` | timestamp | When the decision was made. |
| `agent.id` | string | Stable identifier of the agent that asked. |
| `agent.key` | public key | The key of the daemon that signed the receipt. |
| `action.capability` | string | Capability the action falls under, such as `fs.edit.tests`. |
| `action.tool` | string | The host's tool, such as `Edit` or `Bash`. |
| `action.target` | string | What the action touches: a path, a branch, a host. |
| `action.args_sha256` | string | SHA-256 of the exact arguments; an approval is bound to them. |
| `decision.result` | string | `allow`, `escalate` or `deny`. |
| `decision.level` | integer | The agent's trust level on this capability at the time: 0 ask first, 1 supervised, 2 trusted. |
| `decision.by` | string | What decided: `gate`, `score`, `human` or `predicted`. |
| `decision.review` | `true` | Present only when the allowed action was sampled for a person to review. |
| `sig` | signature | Signature over the receipt without `sig` (section 3). |
| `verification` | object | Present only on a receipt that records an outcome (section 5). |

Rules for every receipt:

- An object MUST NOT hold a key this section doesn't list, at any depth. A verifier MUST fail a receipt
  that does. The canonical bytes are built from the receipt as written, so an implementation that dropped
  unknown keys while parsing would verify a receipt carrying a field nobody signed.
- The two optional keys are written only when they say something. `decision.review` MUST be absent or
  `true`; `false` MUST fail. `verification` MUST be absent or an object; `null` MUST fail.
- A key MUST NOT appear twice in one object. A verifier MUST fail a line that repeats one.
- `seq`, `decision.level` and `verification.of` are non-negative integers. Writers MUST keep them below
  2^53, so every RFC 8785 implementation writes them as plain digits.
- `ts` is recorded, not checked. Nothing in this format proves when a receipt was written; the checkpoints
  published outside the machine (section 6) bound it in time.

## 3. Canonical form, hash and signature

The canonical bytes of a receipt are its JSON Canonicalization Scheme form, as defined in
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): keys sorted, no whitespace, strings escaped as the RFC
says.

- The **signed bytes** are the canonical bytes of the receipt with the `sig` key removed. `sig` MUST be an
  Ed25519 signature ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) over them.
- The **hash** of a receipt is SHA-256 over its canonical bytes with `sig` included.

## 4. Chain

A log is a sequence of receipts, oldest first.

- The receipt at position `i` MUST have `seq` equal to `i`.
- The first receipt's `prev` MUST be `sha256:` followed by 64 zeros.
- Every later receipt's `prev` MUST equal the hash of the receipt before it.

Editing, removing or reordering any receipt therefore breaks the chain at a known position, unless whoever
did it holds the signing key and signs everything after it again. Removing receipts from the end leaves a
shorter chain that still verifies; only a checkpoint kept somewhere else shows it (section 6).

## 5. Outcomes

A receipt that records the checked outcome of an earlier decision carries `verification`:

| Key | Type | Meaning |
|---|---|---|
| `evidence_sha256` | string | SHA-256 of what the verifier looked at: a test log, a diff, a review. |
| `kind` | string | `tests`, `diff`, `replay`, `human`, or `host` for the host's own report that a tool ran. |
| `of` | integer | `seq` of the decision this is the outcome of. |
| `result` | string | `pass`, `fail` or `unknown`. |

An outcome receipt MUST name, in `of`, an earlier receipt that is itself a decision (has no
`verification`), and MUST repeat that decision's `agent`, `action` and `decision` exactly. These rules are
part of Level 3 (section 8). The reference verifier writes outcomes this way but doesn't yet refuse a log
that breaks them; `check.py` checks them on `v1.json`.

## 6. Checkpoint

A checkpoint is a signed statement that the log held `count` receipts and that the last of them hashed to
`head`. It is a JSON object with these keys, and no others:

| Key | Type | Meaning |
|---|---|---|
| `v` | integer | MUST be `1`. |
| `count` | integer | How many receipts the log held. |
| `head` | hash | Hash of the receipt at position `count - 1`. |
| `ts` | timestamp | When it was signed. |
| `sig` | signature | Ed25519 over the canonical bytes of the checkpoint without `sig`. |

A checkpoint with `count` 0 vouches for nothing. For any other checkpoint, a verifier MUST fail the log if
it holds fewer than `count` receipts, or if the hash of the receipt at `count - 1` isn't `head`. A
checkpoint in the log's own directory can be deleted
together with the receipts it covers, so it is the published ones, kept where the log's owner can't
rewrite them, that catch a deleted tail.

## 7. Files

A log directory holds:

- `receipts.jsonl`: one receipt per line, oldest first.
- `checkpoints.jsonl`: the checkpoints the daemon signed, one per line.
- `public.key`: the log's public key, one line.

Lines end in LF. A verifier SHOULD skip blank lines and MUST fail any other line it can't read as one
receipt or checkpoint. Published checkpoints use the same one-object-per-line form wherever they are kept
(a file on another machine, a git repository).

### 7.1 Segments

A log that rotates also holds a `segments/` directory (added in spec 1.1.0). Each file in it is a closed
segment: receipts in the same one-per-line form, named by the `seq` of its first receipt as 20 decimal
digits followed by `.jsonl`, such as `00000000000000004012.jsonl`. `receipts.jsonl` holds the receipts after
the last segment. The chain runs on across files unchanged: the first receipt of a segment links to the
last receipt of the one before.

For a log with a `segments/` directory, a verifier reads `checkpoints.jsonl` as well, and:

- MUST fail a file in `segments/` with any other name;
- reads the segments in order of their names, then `receipts.jsonl`, which may be missing;
- MUST fail when a segment's name isn't the number of receipts read before it, counting from where the
  log starts;
- MUST fail a closed segment unless some checkpoint has `count` equal to the number of receipts in the
  log at its end;
- starts the log at the first segment's number. With no segments left, it starts at the `seq` of the
  first receipt in `receipts.jsonl`, or, with no receipts, at the largest `count` in `checkpoints.jsonl`.
  Starting anywhere but 0 needs a checkpoint with exactly that `count`: its `head` is what the first
  receipt's `prev` must equal, and the verifier MUST fail if checkpoints with that `count` disagree on
  `head` or none exists;
- skips, apart from their signatures, checkpoints for a count at or before the start, since the receipts
  they vouched for were archived.

The checkpoints used are the log's own for Level 1, and the log's own together with the published ones
for Level 2. A log without `segments/` is read exactly as before 1.1.0, so archiving is only possible once
a log has rotated: cutting the start off a log that never rotated still fails.

## 8. Conformance levels

A verifier reports the highest level a log reaches. A tool that writes or checks logs may claim a level
when it passes every vector for that level and every level below it.

**Level 1: a signed hash chain.** Every receipt meets sections 1 to 4 and its signature verifies against
the public key in the log directory. This shows the log hasn't been changed by anyone without the key. It
doesn't show whose key that is, and it doesn't show that nothing was removed from the end.

**Level 2: a pinned key and published checkpoints.** Level 1, and also:

- the verifier was given the public key some way other than the log directory (pinned in a repository,
  sent by the log's owner, taken from a release), and every receipt verifies against that pinned key;
- at least one checkpoint published outside the machine is supplied, every one of them verifies against
  the pinned key, and the log still holds what each vouched for (section 6).

A log rewritten with a new key, or cut short, stays at Level 1. `mohar verify --public-key <file>
--checkpoints <source>` runs the Level 2 checks.

**Level 3: outcomes bound to the work.** Level 2, and also every outcome receipt meets section 5, and
receipts are bound to the commit diff they cover, so a receipt can't be moved onto different code. Format
version 1 has no field for that binding yet. Level 3 will be completed in a minor version of this spec, and
until then no log can claim it.

## 9. Versioning

The spec has its own version number, `MAJOR.MINOR.PATCH`, separate from the `mohar` crates. A release of
one doesn't force a release of the other.

- **MAJOR** changes the receipt's `v`. Anything that changes the bytes of an existing receipt, or turns a
  log that verified into one that doesn't, is a major change.
- **MINOR** adds something optional: a new key that is absent unless used, or a new level. Logs that were
  valid stay valid. Because unknown keys fail (section 2), a verifier written for an older minor version
  fails a receipt that uses a newer key; that is deliberate, since it can't check what it doesn't know.
- **PATCH** clarifies wording or adds test vectors, and changes no rule.

Every version is listed in [the changelog](../CHANGELOG.md) under the crate release that first ships it.

## 10. Test vectors

- [`vectors/v1.json`](vectors/v1.json): a fixed test-only key, four receipts with their canonical bytes,
  hashes and signatures, and a checkpoint. Checks byte-level agreement.
- [`vectors/conformance-v1.json`](vectors/conformance-v1.json): logs that reach Level 2, logs that stop at
  Level 1 (no pinned key, nothing published, a deleted tail, a rewrite with another key, a forged
  checkpoint) and logs that reach no level (a bad signature, a broken link, a removed receipt, uppercase
  hex, an unknown version, unsigned keys), each with the level a verifier must report. Since 1.1.0 it
  also has rotated logs (section 7.1): across segments, with every segment archived, and ones that must
  fail (no checkpoint closing a segment or at the archive point, a missing segment, a segment named at
  the wrong start, conflicting checkpoints, a misnamed file).

The Rust tests regenerate both files from fixed seeds and check every case with the Rust verifier;
`check.py` checks the same files in CI and must agree.

```bash
python spec/vectors/check.py spec/vectors/conformance-v1.json
python spec/vectors/check.py --log .mohar --pinned-key owner.key --checkpoints published.jsonl
```

## 11. Security notes

- Whoever holds the signing key can rewrite anything after the last checkpoint published outside their
  reach. Publish checkpoints often, to a place they can't change.
- A verifier that reads the key from the log directory checks only that the log agrees with itself. Pin
  the key.
- The format records decisions and outcomes; it doesn't make them correct.
