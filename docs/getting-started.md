# Install and first log

## Install

Each [release](https://github.com/harshitwandhare/mohar/releases) has `mohar` for Linux and macOS
(x86_64 and arm64) and Windows (x86_64).

=== "Linux and macOS"

    ```bash
    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/harshitwandhare/mohar/releases/latest/download/mohar-cli-installer.sh | sh
    ```

=== "Windows"

    ```powershell
    powershell -ExecutionPolicy Bypass -c "irm https://github.com/harshitwandhare/mohar/releases/latest/download/mohar-cli-installer.ps1 | iex"
    ```

=== "From source"

    ```bash
    git clone https://github.com/harshitwandhare/mohar && cd mohar
    cargo install --path crates/mohar-cli --locked
    ```

Check the install with `mohar --version`.

### Verify what you downloaded

Every release artefact carries a GitHub build attestation proving it was built by this repository's
release workflow:

```bash
gh attestation verify mohar-cli-x86_64-unknown-linux-gnu.tar.xz -R harshitwandhare/mohar
```

## Your first log

Create a log. This writes a fresh signing key, readable only by you on Linux and macOS, and an empty
receipt file into `.mohar/`:

```bash
mohar init
```

Record a decision about an agent action:

```bash
mohar append --agent agent:me/1 --capability fs.edit.docs --tool Edit \
  --target docs/a.md --args-sha256 c41b77d0 --result allow --level 1 --by score
```

Look at the log and check it:

```bash
mohar log
mohar verify
# ok: 1 receipts and 0 checkpoints verified
```

## See it catch tampering

Change any receipt in `.mohar/receipts.jsonl`, for example `"allow"` to `"deny"`, and run
`mohar verify` again. It names the receipt that broke and why, and exits with status 1:

```text
broken: receipt 0: BadSignature
```

While the log is broken, Mohar won't add to it:

```text
$ mohar checkpoint
mohar: chain does not verify: receipt 0: BadSignature
```

Put the original line back. A hash chain alone can't tell you receipts were deleted from the end.
Checkpoints can:

```bash
mohar checkpoint
# delete the last line of .mohar/receipts.jsonl, then:
mohar verify
# broken: checkpoint 0: log should hold 1 receipts, holds 0
```

Only the public key is needed to verify, so you can hand the `.mohar` directory without
`key.ed25519` to someone else and they can check it without being able to add to it.
