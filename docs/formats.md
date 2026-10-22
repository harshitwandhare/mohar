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

## Checkpoint

One JSON object per line in `checkpoints.jsonl`:

```json
{"v": 1, "count": 3, "head": "sha256:...", "ts": "2026-11-03T15:00:00.000Z", "sig": "ed25519:..."}
```

`count` is how many receipts the log held, `head` is the hash of the receipt at `count - 1`, and `sig` is
Ed25519 over the canonical JSON without `sig`. A verifier fails if the log holds fewer receipts than a
checkpoint vouched for, or a different receipt at that position.

## Test vectors

[`spec/vectors/v1.json`](https://github.com/harshitwandhare/mohar/blob/main/spec/vectors/v1.json) holds
a fixed test-only key, three receipts with their canonical bytes, hashes and signatures, and a
checkpoint. The Rust tests regenerate it byte for byte, and
[`spec/vectors/check.py`](https://github.com/harshitwandhare/mohar/blob/main/spec/vectors/check.py)
checks it in Python with no code shared with the Rust implementation. To test another implementation:

1. rebuild each receipt's canonical bytes and compare them with `canonical_hex`;
2. hash them and compare with `sha256` and with the next receipt's `prev`;
3. verify each `sig` against `public_key` over the canonical bytes without `sig`;
4. check the checkpoint's `head`, `count` and signature the same way.
