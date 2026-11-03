# Mohar receipts, format version 1

Spec version 1.4.0

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
| `decision.to` | array of strings | Present only on an escalation that was routed to named people (added in 1.4.0): any one of them may answer. In strict privacy mode, pseudonyms like `agent.id`. |
| `sig` | signature | Signature over the receipt without `sig` (section 3). |
| `verification` | object | Present only on a receipt that records an outcome (section 5). |
| `person` | object | Present only on a receipt that records what a person did (section 5.1, added in 1.2.0). |

Rules for every receipt:

- An object MUST NOT hold a key this section doesn't list, at any depth. A verifier MUST fail a receipt
  that does. The canonical bytes are built from the receipt as written, so an implementation that dropped
  unknown keys while parsing would verify a receipt carrying a field nobody signed.
- The optional keys are written only when they say something. `decision.review` MUST be absent or
  `true`; `false` MUST fail. `decision.to`, when present, MUST be a non-empty array of strings; `[]` MUST fail. `verification` and `person` MUST each be absent or an object; `null` MUST
  fail. Inside `person`, `lesson` and `until` MUST be absent or set; `null` MUST fail.
- A key MUST NOT appear twice in one object. A verifier MUST fail a line that repeats one.
- `seq`, `decision.level`, `verification.of` and `person.until` are non-negative integers. Writers MUST keep them below
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

### 5.1 Person acts

Added in spec 1.2.0; `approve` added in 1.3.0 and `refuse` in 1.4.0. A person can change the trust state in
five ways, and each one is a receipt of its own that carries `person`:

| Key | Type | Meaning |
|---|---|---|
| `act` | string | `promote` a lesson to the team, `release` an agent's quarantined lessons, `extend` a remediation plan's deadline, or `approve` or `refuse` one escalated action. |
| `by` | string | Stable identifier of the person. In strict privacy mode, a pseudonym like `agent.id`. |
| `lesson` | hash | For `promote` only: the hash of the failed outcome receipt the lesson was learned from. |
| `until` | integer | For `extend`: the new deadline. For `approve`: when the approval lapses unused. Seconds since the Unix epoch. |

The rest of the receipt says what the act applies to. `agent.id` is the agent concerned. `action.capability`
is the capability (empty for `release`, which covers all of the agent's lessons), `action.tool` is
`mohar`, `action.target` is empty, and `action.args_sha256` is the SHA-256 of the canonical `person`
object without `by`. `decision` is `{"result": "allow", "level": 0, "by": "human"}`.

A person receipt MUST NOT carry `verification`. `lesson` MUST be present exactly when `act` is `promote`,
`until` exactly when it is `extend`, and `action.capability` MUST be empty exactly when it is `release`.
A person receipt is never a decision waiting for an outcome. These rules are part of Level 3, like
section 5's; the reference daemon writes person receipts this way and, when it replays a log, lets one
that breaks them change nothing.

`approve` and `refuse` receipts are different in one way: `agent` and `action` are the escalated action itself,
copied exactly, so what was answered is signed rather than pointed to. `action.tool` is the host's tool,
never `mohar`, `action.capability` is not empty and `lesson` is absent; `until` is present on `approve` and
absent on `refuse`. `by` SHOULD be one of the escalation's `decision.to`. Either answer closes every
escalated decision of that action by that agent. The approval is
bound to the SHA-256 of the action's canonical form (RFC 8785, the four `action` keys only), which is what
the person was shown. An approval lets the next
decision for exactly that action, before `until`, be `{"result": "allow", "by": "human"}`. That decision
uses the approval up; a later one needs another.

Who the person is rests on whoever runs the daemon: `by` is recorded, not authenticated. Binding it to a
key the person holds is future work.

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

**Level 3: outcomes bound to the work.** Level 2, and also every outcome receipt meets section 5, every
person receipt meets section 5.1, and
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
  the wrong start, conflicting checkpoints, a misnamed file). Since 1.2.0 it has a log with a person
  receipt (section 5.1) and three that add a null or unknown key to one after it was signed.

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

## 12. Mapping to other formats

Two individual Internet-Drafts describe signed, chained records of what an agent did. Neither is an IETF
standard. [`spec/vectors/export.py`](vectors/export.py) converts the `person-receipt` conformance log into
both, signs the result again with the test seed (neither format signs the bytes Mohar signs), and checks
it against each draft's own rules. CI rebuilds both files in [`spec/vectors/export/`](vectors/export/)
and fails if they change or if either check fails. The export is one way: nothing reads these formats
back into Mohar.

Both drafts were read on 2026-11-01.

### 12.1 draft-sharif-agent-audit-trail-09 (26 October 2026)

| Mohar | sharif-09 | Notes |
|---|---|---|
| `seq` | `sequence_number` | Same meaning. |
| `prev` | `prev_hash` | Recomputed: SHA-256 of the previous record's JCS form, plain hex, `null` for the first. |
| `ts` | `timestamp` | Copied. |
| `agent.id` | `agent_id` | Prefixed `urn:mohar:agent:` to make it a URI. |
| `agent.key` | `principal.principal_id`, `signer_kid` | The daemon that signed, as a `service` principal. |
| `action.tool` | `action_detail.tool_name` | |
| `action.args_sha256` | `action_detail.parameters_hash` | |
| `action.capability`, `action.target` | none | Lost. `policy_ref` carries the capability on person records only. |
| `decision.result` | `outcome` | allow to `success`, escalate to `escalated`, deny to `denied`. |
| `decision.by` = `human` | `human_override` | The operator is not in a v1 decision receipt, so `operator_id` is `unknown`. |
| `decision.level`, `decision.by`, `decision.review` | none | Lost. `trust_level` means identity assurance there, not earned trust. |
| `verification` | `action_type` `tool_response`, `action_detail.output_hash`, `outcome` | pass to `success`, fail to `failure`. |
| `verification.kind`, `verification.of` | none | Lost; `parent_record_id` links to the previous record, not to the decision. |
| `person` | `action_type` `decision`, `decision_type` `mohar.<act>`, `human_override.operator_id` | `until` and `lesson` are lost. |
| `sig` | `signature`, `sig_alg` `Ed25519` | A new signature over SHA-256 of the JCS form, base64url. |

Fields sharif-09 requires that Mohar doesn't record, and what the export writes: `record_id` and
`session_id` (UUIDs derived from a hash, version bits set), `agent_version` (`0.0.0`), `trust_level`
(`L0`: the agent itself holds no key), `principal.authority_ref` (`null`), `record_phase` (`pre_execution`
for decisions, `post_execution` for outcomes, `concurrent` for person acts).

### 12.2 draft-sahu-agent-action-receipts-00 (16 August 2026)

| Mohar | sahu-00 | Notes |
|---|---|---|
| `seq` | `step_id` | As a decimal string. |
| `action.tool` | `action_id` | |
| `action`, `decision`, `verification`, `person` | `params` | Kept whole, plus `mohar_seq`, so nothing is lost. |
| `decision.result`, `verification.result` | `success` | `true` for allow, a pass, or a person act; `false` otherwise. |
| `ts` | `ts_ms` | Milliseconds since the epoch. |
| `agent.id` | `actor.agent` | |
| `prev` | `prev_hash` | Recomputed over the exact bytes of the previous line, absent on the first. |
| `agent.key`, `sig` | `public_key`, `signature` | A new Ed25519 signature over the draft's ordered bytes, in hex. |

### 12.3 Open questions for the drafts' authors

- sharif-09 requires `record_id` and `session_id` to be UUIDv4, which is random. A converter that must
  give the same output for the same input can only derive them from a hash with the version bits set.
  Is a hash-derived identifier with version 4 acceptable, or should the draft allow UUIDv8 or any string?
- sharif-09's `trust_level` measures how well the agent's identity is attested. A record has no field
  for authority the agent has earned on a kind of action. Would the authors take an optional field for
  it, or should it go inside `action_detail`?
- sharif-09 has no outcome for "the tool ran, nothing checked it yet". Mohar's `unknown` result is
  written as `success`, which overstates it. Would `unverified` fit the `outcome` list?
- sharif-09 links an outcome to the record before it (`parent_record_id`), not to the decision it
  answers. Is `authorization_record_id`, defined for `decision`, meant for that on `tool_response`?
- sahu-00 tells verifiers to ignore members it doesn't define and leave them out of the signed bytes.
  An unsigned member can then ride along on a valid receipt, the problem section 2 of this spec refuses
  by failing any unknown key. Would the draft consider refusing them, or signing them?
- sahu-00 hashes the exact bytes of the previous line, so any re-serialization breaks the chain, while
  the signature covers a canonical form. A log rewritten in canonical form keeps valid signatures and
  loses its chain. Is that intended?

