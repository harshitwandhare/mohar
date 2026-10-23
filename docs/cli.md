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

## `mohar daemon [--addr <host:port>] [--max-inflight <n>]`

Serves decisions and outcomes to agent hosts on this machine, from the log in `--dir`, which it holds
open for writing while it runs. It listens on `127.0.0.1:7878` by default and refuses any address that
isn't loopback. It prints `listening on <address>` once bound, and how many earlier decisions are still
waiting for an outcome.

Two endpoints, JSON in and out:

```
POST /v1/decide   {agent, tool, target, args_sha256, call_id?}  ->  {result, level, receipt_seq}
POST /v1/outcome  {receipt_seq | call_id, verifier, result, evidence_sha256}  ->  {receipt_seq}
POST /v1/verify   {agent, task}  ->  {verified, result}
```

`/v1/verify` verifies a finished task: it runs the project's test command (below) once and records the
result as a `tests` outcome for every decision in the task that ran and changes something. `decide`
requests name their task with `task` (the Claude Code hook sends the session id). If the agent changed one
of the project's test files in the task, the result is `fail` whatever the tests say. No command, a
command that can't start, or one that runs past its timeout gives `unknown`, which never counts.

`result` is `allow`, `escalate` or `deny`. `verifier` is `tests`, `diff`, `replay`, `human` or `host`;
`host` is the host's own report that a tool ran and never counts toward trust. Unknown fields, bad hashes
and oversized bodies are refused with a 4xx and recorded nowhere. Past `--max-inflight` requests at once
(default 64) the daemon answers 503 rather than queueing.

The daemon decides which capability an action falls under from its policy (below); a request can't name
one. The trust engine then answers from the agent's verified record on that capability (design, section
4): actions with risk `none` run; at Ask first everything else goes to a person; at Supervised low-risk
reversible actions run; at Trusted actions run inside the capability's gates; an irreversible high-risk
action always goes to a person; a suspended agent is denied. Every answer is a signed receipt.

Trust is rebuilt from the log each time the daemon starts, by replaying every verified outcome; it is
stored nowhere else. An outcome counts only from a real verifier (`tests`, `diff`, `replay`, `human`)
with a `pass` or `fail` result; a `host` report or an `unknown` result never does. A failure's severity
comes from its capability: low-risk reversible failures are minor, medium-risk ones meaningful, and
high-risk or irreversible ones serious. Until remediation plans can name what a pass must exercise
(#87), every verified pass counts toward ending remediation.

### The policy file

The daemon reads `<dir>/policy.json` when it starts and refuses to start if the file is invalid. Without
one it uses a built-in policy rooted at its working directory. A policy names capabilities and an ordered
list of rules; the first rule that matches an action's tool and target wins:

```json
{
  "version": 1,
  "root": "..",
  "capabilities": {
    "fs.edit.docs": { "risk": "low",  "reversible": true,  "ceiling": 2 },
    "db.migrate":   { "risk": "high", "reversible": false, "ceiling": 1 }
  },
  "rules": [
    { "tools": ["Edit", "Write"], "paths": ["docs/**"], "capability": "fs.edit.docs" },
    { "tools": ["Bash"], "commands": ["*migrate*"], "capability": "db.migrate" }
  ]
}
```

- `risk` is `none`, `low`, `medium` or `high`; `ceiling` is the highest level an agent may reach on the
  capability, 0 to 2, and a high-risk irreversible capability can't go above 1.
- A rule gives either `paths` (globs over the target relative to `root`, where `*` and `?` stay within a
  directory and `**` crosses directories) or `commands` (globs over the whole command line, where `*`
  matches anything), never both. `tools` limits it to those host tools.
- `root` defaults to the directory that holds the log directory. `..` in a target is resolved first, so a
  path can't climb out of the root.
- An action that matches no rule, or names a path outside the root, is `unclassified`: high risk,
  irreversible, ceiling 0.
- Unknown fields, unknown capability names in rules and the reserved name `unclassified` are refused.

### Verification

```json
"verify": {
  "tests": {
    "command": ["cargo", "test", "--locked"],
    "timeout_secs": 600,
    "test_paths": ["tests/**", "**/*_test.*"]
  }
}
```

`command` is run directly from the root, with no shell, so nothing in it is interpreted. The evidence
recorded is the SHA-256 of the exit status and everything the command printed.

### Gates

Gates are checked before any trust score, and no record outweighs them. A gate stop is a `deny` receipt
with `by: gate`, and the answer names the gate and the reason, which the Claude Code hook shows the
person. A gate that can't decide (a write with no path, a URL it can't parse) refuses.

```json
"gates": {
  "deny_capabilities": ["git.push.main"],
  "allowed_hosts": ["api.github.com", "*.example.com"],
  "protected_paths": [".mohar/**", "tests/**"]
}
```

- Writes (`Edit`, `MultiEdit`, `Write`, `NotebookEdit`) outside the project root are always refused.
- `deny_capabilities`: capabilities no agent may use at any level; each must be defined.
- `allowed_hosts`: when set, a `WebFetch` URL or any URL in a command line must go to a listed host;
  `*.example.com` matches subdomains only. When absent, this gate is off.
- `protected_paths`: globs (relative to the root) no agent may write to.

The built-in policy denies `git.push.main` and protects `.mohar/**`, so an agent can't rewrite its own
policy or log.

The built-in policy (`mohar_core::policy::BUILTIN`) is a fuller example: reads, docs, tests, code and
config edits, read-only shell commands, pushes to a branch and to the default branch.

After a crash, decisions without an outcome are rebuilt from the log on the next start and can still be
given one by `receipt_seq`; `call_id`s live only for the life of the process.

## `mohar hook claude-code [--daemon <url>]`

The command Claude Code runs for `PreToolUse` and `PostToolUse`. It reads the hook payload on stdin, asks
the daemon, and prints Claude Code's `permissionDecision`: `allow`, `ask` (for `escalate`) or `deny`. It
denies when the daemon can't be reached, answers with an error, or the payload can't be read, and it only
ever talks to a loopback address. `PostToolUse` is recorded as a `host` outcome matched by `tool_use_id`.
Subagents are identified as `agent:claude-code/<agent_type>`, the main agent as `agent:claude-code/main`.
On `Stop` and `SubagentStop` it asks the daemon to verify the session's task, and reports the result on
stderr.
