# CLI reference

`mohar [--dir <path>] <command>`

`--dir` is the log directory, `.mohar` by default. It applies to every command.

Exit status: `0` on success, `1` when `verify` finds a break, `2` on any other error (the message goes
to standard error).

## `mohar init`

Creates a new log in `--dir`: `key.ed25519` (the signing seed, owner-only on Unix), `public.key`,
an empty `receipts.jsonl` and `checkpoints.jsonl`. Refuses to touch a directory that already holds a
log.

## `mohar append`

Signs and appends one receipt, then prints its sequence number. The receipt is synced to disk before
the command returns.

| Flag | Meaning |
|---|---|
| `--agent` | Agent identifier |
| `--capability` | Capability the action falls under, such as `fs.edit.docs` |
| `--tool` | The host tool that would run it |
| `--target` | The path, branch or host it acts on |
| `--args-sha256` | SHA-256 of the exact arguments |
| `--result` | `allow`, `escalate` or `deny` |
| `--level` | The agent's trust level on this capability (default `0`) |
| `--by` | What decided it: `gate`, `score`, `human` or `predicted` (default `human`) |

Opening the log verifies the whole chain and its checkpoints first; a log that doesn't verify is
refused rather than extended. Only one process may write to a log at a time.

## `mohar checkpoint`

Signs a checkpoint over the log as it stands (how many receipts, and the hash of the last one). A
checkpoint is also written automatically every 1,000 receipts.

## `mohar log [--last N]`

Prints receipts, oldest first, one per line. Doesn't need the signing key or the writer lock.

## `mohar verify [--public-key <file>]`

Checks every receipt and every checkpoint against the public key (`public.key` in the log directory
by default). Prints `ok: ...` or the first break with its index and reason. Doesn't need the signing
key, so anyone can verify a log they were given.
