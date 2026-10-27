# Receipts and checkpoints

## Receipt

One JSON object per line in `receipts.jsonl`. The full field list and the reasoning behind it are in
[the design, section 7](design.md#7-receipts).

- **Signature**: Ed25519 over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON of
  the receipt with `sig` left out.
- **Chain**: `prev` is `sha256:` followed by the SHA-256 of the previous receipt's canonical JSON,
  signature included. The first receipt's `prev` is `sha256:` followed by 64 zeros.
- **Sequence**: `seq` is the receipt's position, starting at 0.
- **Version**: `v` is `1`. A verifier refuses versions it doesn't know.
- **Outcome**: a follow-up receipt that records the outcome of an earlier decision carries a
  `verification` object, `{"evidence_sha256", "kind", "of", "result"}`, where `of` is the `seq` of the
  decision, `kind` is the verifier (`tests`, `diff`, `replay`, `human`, or `host` for the host's own report
  that a tool ran) and `result` is `pass`, `fail` or `unknown`. It repeats the decision's agent, action
  and decision. Receipts without an outcome have no `verification` key at all, so their bytes, and every
  existing test vector, are unchanged; `verification` sorts last in the canonical form.
- **Review sample**: a decision the agent's record allowed may carry `"review": true` inside `decision`,
  meaning the action was drawn for a person to check after it ran (20% at Supervised, 5% at Trusted).
  The draw is SHA-256 over a seed derived from the signing key and the receipt's `seq`, so whoever holds
  the key can recompute it. The key is left out when false, so older receipts read the same, and it is
  signed like every other field.

## Checkpoint

One JSON object per line in `checkpoints.jsonl`:

```json
{"v": 1, "count": 3, "head": "sha256:...", "ts": "2026-10-14T15:00:00.000Z", "sig": "ed25519:..."}
```

`count` is how many receipts the log held, `head` is the hash of the receipt at `count - 1`, and `sig` is
Ed25519 over the canonical JSON without `sig`. A verifier fails if the log holds fewer receipts than a
checkpoint vouched for, or a different receipt at that position.

## Test vectors

[`spec/vectors/v1.json`](https://github.com/harshitwandhare/mohar/blob/main/spec/vectors/v1.json) holds
a fixed test-only key, four receipts (three decisions and the outcome of the first) with their canonical
bytes, hashes and signatures, and a
checkpoint. The Rust tests regenerate it byte for byte, and
[`spec/vectors/check.py`](https://github.com/harshitwandhare/mohar/blob/main/spec/vectors/check.py)
checks it in Python with no code shared with the Rust implementation. To test another implementation:

1. rebuild each receipt's canonical bytes and compare them with `canonical_hex`;
2. hash them and compare with `sha256` and with the next receipt's `prev`;
3. verify each `sig` against `public_key` over the canonical bytes without `sig`;
4. check the checkpoint's `head`, `count` and signature the same way.
