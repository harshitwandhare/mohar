# CLI reference

`mohar [--dir <path>] [--segment-mib <n>] <command>`

`--dir` is the log directory, `.mohar` by default. It applies to every command.

`--segment-mib` is the size at which `append` and the daemon close `receipts.jsonl` into a segment, 64 by
default; `0` never rotates. Closing a segment signs a checkpoint for the log as it stands, moves the file
to `segments/<seq of its first receipt>.jsonl` (20 digits) and starts an empty `receipts.jsonl`. Old
segments can be archived or deleted oldest first: `verify` then starts from the checkpoint that closed
the last one removed, and fails if that checkpoint is gone or a segment is missing between two that
remain. The daemon rebuilds trust from the segments still present, so outcomes in archived segments
stop counting.

Exit status: `0` on success, `1` when `verify` finds a break, `2` on any other error (the message goes
to standard error).

## `mohar init [--strict-privacy]`

Creates a new log in `--dir`: `key.ed25519` (the signing seed, owner-only on Unix), `public.key`,
an empty `receipts.jsonl` and `checkpoints.jsonl`. Refuses to touch a directory that already holds a
log.

`--strict-privacy` is for deployments where a file path or an agent name can itself be personal data,
such as notes about patients. It adds `privacy.key`, a second 32-byte secret kept beside the signing
key, and from then on every agent id and target goes into `receipts.jsonl` only as
`hmac-sha256:<hex>`, the HMAC-SHA-256 of the value under that secret. The same value always gets the
same pseudonym, so trust still adds up per agent. The clear value is written to `identities.jsonl`,
one `{"id": ..., "value": ...}` line per pseudonym, synced before the receipt that uses it. That file
is outside the chain: delete a line to erase someone, or the whole file to erase everyone, and
`mohar verify` still passes because verification needs neither file. A log in this mode refuses to
open for writing once `privacy.key` is gone, so new receipts are never written in the clear by
accident. The mode is chosen at `init` and can't be switched on or off later.

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

## `mohar checkpoint [--publish <file | git:<clone>>]`

Signs a checkpoint over the log as it stands (how many receipts, and the hash of the last one). A
checkpoint is also written automatically every 1,000 receipts.

A checkpoint kept only beside the log can be deleted along with the receipts it covers. `--publish`
also sends the new checkpoint somewhere outside the log directory (the command refuses a target inside
it):

- a file: the checkpoint is appended to it. This only helps if the file lives where the log's operator
  can't rewrite it, such as another machine or an append-only share.
- `git:<clone>`: a clone of a git repository. Mohar pulls (fast-forward only), appends the checkpoint to
  `checkpoints.jsonl` at the top of the clone, commits and pushes, using git's own configuration for
  the commit author and credentials. If any step fails the command exits 2 and says the checkpoint was
  not published; it is still signed and kept in the log directory.

What a git target protects against: an operator who can write to the machine with the log but not to
the remote's history. That holds when the remote is a branch they can't force-push or delete, in a
repository someone else administers. What it doesn't protect against: anyone who can rewrite that
branch, an operator who stops publishing (the remote then shows the last checkpoint that reached it,
which is still enough to catch receipts removed before it), or a stolen signing key. Other URLs are
refused rather than written as local paths.

## `mohar log [--last N]`

Prints receipts, oldest first, one per line, across every segment still present. Doesn't need the
signing key or the writer lock.

## `mohar verify [--public-key <file>] [--checkpoints <file | git:<clone>>]... [--trust-checkpoints] [--from <count>]`

Checks every receipt and every checkpoint against the public key (`public.key` in the log directory
by default). Prints `ok: ...` or the first break with its index and reason. Doesn't need the signing
key, so anyone can verify a log they were given.

`--checkpoints` adds published checkpoints to the check and can be given more than once. A `git:` source
is pulled first, so an auditor's own clone sees what was pushed. A log that
lost receipts and its own checkpoints together still fails against them. A file named here that can't
be read, or a clone that can't be pulled, is an error (exit 2), never an empty list.

`--trust-checkpoints` checks signatures only on receipts after the furthest checkpoint, once every
checkpoint's own signature has verified. Receipts before it are still parsed, hashed and linked, so a
change to any of them still fails; this is about five times faster on a log that is mostly covered by
checkpoints. It can't catch a receipt the key holder wrote with a bad signature before a checkpoint, so
leave it off when auditing someone else's log. The design notes (receipt format) give the argument.

`--from <count>` starts at the signed checkpoint for that many receipts and reads nothing before it,
for an auditor who already checked the log up to there. It is an error (exit 1) when no checkpoint has
that count. The receipt after the checkpoint must link to its head, and every line after the start
counts, so an old receipt copied further down still fails. The output then names the range checked:
`ok: receipts 2 to 3 (2 of 4) and 1 checkpoints verified`.

## `mohar daemon [--addr <host:port>] [--max-inflight <n>] [--otlp-endpoint <url>]`

Serves decisions and outcomes to agent hosts on this machine, from the log in `--dir`, which it holds
open for writing while it runs. It listens on `127.0.0.1:7878` by default and refuses any address that
isn't loopback. It prints `listening on <address>` once bound, then, if any earlier decisions are still
waiting for an outcome, a line naming them: `waiting for an outcome: 2 decisions (receipts 1, 5)`
(the first ten, then how many more).

Crash safety: every receipt is synced to disk before the daemon answers, so a daemon killed between a
decision and its outcome loses nothing. On the next start it verifies the log, rebuilds the decisions
still waiting from it and lists them as above; each can be given its outcome by `receipt_seq`.

Overload: at most `--max-inflight` requests (default 64) are handled at once. Past that the daemon
answers 503 with `{"error": "too many requests in flight"}` straight away, writes nothing, and queues
nothing; a slot frees as soon as its request ends or times out (5 seconds). The hook treats a 503 like
any refusal and denies.

Telemetry: with `--otlp-endpoint http://127.0.0.1:4318` the daemon sends OpenTelemetry over OTLP/HTTP with
JSON bodies to a collector on this machine; it refuses an endpoint that isn't a loopback address, so
nothing leaves the machine unless that collector forwards it. Every half second it sends a `mohar.decide`
span for each decision (attributes `mohar.result`, `mohar.by`, `mohar.capability`, `mohar.receipt_seq`)
and cumulative metrics: `mohar.decisions` by result, `mohar.outcomes` by verifier and result,
`mohar.decide.duration` (a histogram in milliseconds) and `mohar.inflight`. Spans carry no agent ids,
targets or arguments. Export runs on its own thread; a collector that is down or slow loses telemetry
and never delays or changes a decision. Without the flag nothing is collected.

Eight endpoints, JSON in and out:

```
POST /v1/decide   {agent, tool, target, args_sha256, call_id?}  ->  {result, level, receipt_seq, lessons}
POST /v1/outcome  {receipt_seq | call_id, verifier, result, evidence_sha256, reviewer?, review_secs?}  ->  {receipt_seq}
POST /v1/verify   {agent, task}  ->  {verified, result}
POST /v1/person   {by, act, agent, capability?, lesson?, until?}  ->  {receipt_seq}
POST /v1/approve  {receipt_seq, by, action_sha256}  ->  {receipt_seq, until}
POST /v1/refuse   {receipt_seq, by, action_sha256}  ->  {receipt_seq}
POST /v1/escalation  {receipt_seq}  ->  {agent, action, action_sha256, to, level, passes, failures, suspended}
POST /v1/predictions  {}  ->  {people: {<id>: {predicted_today, checks, agreed}}}
```

When the policy has a `people` section, an `escalate` answer from `/v1/decide` also carries `approver`:
`to` (the people who may answer), `via` (`delegator`, `reporting_tree` or `owners`) and `action_sha256`,
the SHA-256 of the exact action as canonical JSON. One of them approves with `/v1/approve`, naming that
hash. Someone the escalation wasn't routed to gets a 403, and a hash of any other action gets a 409; in
both cases nothing is written. An approval is a signed receipt (receipt spec section 5.1) that lets that
agent run that exact action once within the hour: the next `/v1/decide` for it is `allow`, decided by
`human`, and a different target, different arguments or a different agent still escalate. Gates and
suspensions are checked first and an approval never overrides them. `/v1/refuse` takes the same body
and records a no, which closes the escalation without letting anything run. The escalate receipt names
the people it went to (`decision.to`), so an answer is checked against the log and still works after a
restart, as do unused approvals. An escalation that named nobody went to the host's prompt and gets a
403 here. The Claude Code hook denies a routed
escalation with the approvers' names instead of asking whoever is at the prompt.

A `human` outcome must name the `reviewer` and the `review_secs` they spent (any other verifier gets a 400
if it sends them). Both are signed into the receipt, and the reviewer goes through the pseudonyms in
strict privacy mode. A person's accept counts toward trust only if they spent at least 30 seconds and
haven't approved more than 95% of their last 50 reviews; a reject always counts. The daemon rebuilds
each reviewer's window and flag from the log on start.

`/v1/person` records what a person did as a signed receipt (receipt spec section 5.1) and applies it:
`promote` with `lesson` (the `failure` hash from a lesson) shares that lesson with every agent on its
capability; `release` lets an agent's quarantined lessons through again; `extend` with `capability` and
`until` (seconds since the epoch) moves a remediation plan's deadline later. An act that would change
nothing, such as releasing an agent with no quarantine or moving a deadline earlier, gets a 409 and writes
nothing. The daemon replays these receipts on start, so they survive a restart. `by` is recorded as
given; the daemon only listens on loopback, and anyone who can reach it can name any person.

Lessons: every verified failure (any verifier but `host`, and only `fail`, never `unknown`) becomes a
lesson for that agent on that capability, signed with the log's key. `/v1/decide` returns the five most
recent for the capability it classified, oldest first, each as `{at, finding, failure, fix}`: when it
was verified (seconds since the epoch), what failed (`the tests verifier failed Edit on docs/a.md`), the
hash of the outcome receipt that failed, and the hash of the next verified pass by that agent on that
capability, or `null` until there is one. After an S3 or S4 failure the agent's lessons up to then are
withheld until a person releases them, apart from the lesson of that failure itself. The book is rebuilt from the outcome receipts on every start, so
there is no separate file to edit or lose. In strict privacy mode the finding names the pseudonymous
target, as the receipt does.

The Claude Code hook hands these lessons to the agent with the call, as the hook's `additionalContext`:
one line per finding, each cut at 300 characters, with "(since fixed)" once a later pass fixed it.
Without lessons the hook adds no context.

When the classified capability is under a remediation plan, the answer also carries `remediation`:
`{verifier, passes_left, deadline, overdue}`, or `null` without one. A plan is overdue once its deadline
has passed; from then on passes stop counting until a person extends it. The daemon prints one
`remediation overdue: <agent> on <capability>` line per overdue plan when it starts, and the hook adds
the same notice to the reason a person sees.

`/v1/verify` verifies a finished task and records one outcome for every decision in the task that ran and
changes something, from the first verifier that fails:

1. `diff`: in a git repository, the files that changed since the task began (renames under both names,
   the log directory excluded) must all fall under capabilities the agent was given in the task. Any that
   don't are returned as `out_of_scope` and the task fails. Outside a git repository this check is
   skipped.
2. `tests`: the project's test command (below), run once.

One outcome per decision, so a single action never counts twice. `decide`
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
  directory and `**` crosses directories) or `commands` (globs over a command, where `*` matches
  anything), never both. `tools` limits it to those host tools.
- A `Bash` command line is split into the commands it runs (at `;`, `&&`, `||`, `|`, `&`, newlines and
  subshell brackets, with quotes and escapes respected) and each one is matched on its own. The riskiest
  decides the line's capability, and a denied capability anywhere in the line stops all of it, so
  `ls && git push origin main` is a push to main. A line Mohar can't read through (command or process
  substitution, a here-document, `eval`, `source`, a shell run with `-c`, an unclosed quote) is
  `unclassified` and refused. When `allowed_hosts` is set, a command that uses a variable next to a
  URL or a network program (`curl $HOST/x`) is refused too, since the host can't be known.
- Output redirection is a write. `ls > notes.md` is classified as a `Write` to `notes.md` as well as an
  `ls`, the riskier of the two deciding, and the target goes through the same gates as an edit, so
  `echo x > .mohar/policy.json` is refused as a protected path. `>`, `>>`, `>|`, `&>`, `2>` and `<>`
  all count; copying a descriptor (`2>&1`) and writing to `/dev/null`, `/dev/stdout` or `/dev/stderr`
  don't. A target Mohar can't name before the shell runs (a variable, a glob, a `~`) is refused.
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

Capabilities that touch the same paths, hosts or database can be grouped into scopes. When a failure on
a high-risk or irreversible capability drops it to Ask first, every other capability in its scopes drops
with it, for that agent only. Each name must be defined under `capabilities`.

```json
"scopes": {
  "prod-db": ["db.migrate.prod", "db.seed.prod"]
}
```

`gates.two_person` lists capabilities whose escalations need two different people to approve. Such an
escalation also goes to the owners, so there are two people to ask; it stays open after the first
approval, the same person approving again gets a 409, a refusal by anyone asked ends it, and the action
runs only once both have approved. Separately, an agent's sponsor (the person a delegation names as
having handed it authority) can't `release` it after a serious failure: `/v1/person` answers 403 and a
different person has to.

A `people` section routes escalations. The person who delegated to the agent decides if they hold the
capability; otherwise the first person up their reporting tree who does; otherwise any owner. `holds` and
`agent` are globs (`*` matches anything). Owners are required, every name in `reports_to` and `from` must
be listed under `members`, and a reporting line that loops is refused. Without the section, the host's own
prompt decides.

```json
"people": {
  "owners": ["user:owner-1"],
  "members": {
    "user:dev-1": {"holds": ["fs.edit.docs"], "reports_to": "user:lead-1"},
    "user:lead-1": {"holds": ["fs.edit.*"]}
  },
  "delegations": [{"agent": "agent:claude-code/*", "from": "user:dev-1"}]
}
```

#### Predicted answers

A member can let the daemon answer some escalations for them, from their own past answers. `predict`
names the capabilities, each with the paths the target must match and how many answers a day may be
predicted:

```json
"user:dev-1": {
  "holds": ["fs.edit.docs"],
  "predict": {"fs.edit.docs": {"paths": ["docs/guide/**"], "per_day": 20}}
}
```

The daemon keeps each person's approvals and refusals of escalations and trains a calibrated logistic
regression on them (`mohar_core::predict`). When an escalation goes to that one person, on a capability
they switched on, inside their paths and daily count, and the model puts the chance of yes at 0.98 or
more, the daemon answers yes for them. The receipt says `"by": "predicted"` and names them in
`decision.to`, and `/v1/decide` returns `predicted` (`by` and `p_yes`) instead of `approver`. It never
answers no: anything else goes to the person as before. A model needs 30 answers and, for someone who
always says yes, about 50 before it is sure enough.

One prediction in twenty still goes to the person as an ordinary escalation, and isn't marked as a check.
Their answer to it counts toward `/v1/predictions`: `checks` is how many they answered, `agreed` how many
of those were yes, as the model would have said. `predicted_today` is today's count against `per_day`
(UTC days). All of it is rebuilt from the log on start.

Loading the policy fails if `predict` names a capability that is above low risk, can't be undone, needs
two people (`gates.two_person`), or isn't one the person holds, or has no paths or a `per_day` of 0. An
escalation that goes to several people, such as every owner, is never predicted. Nothing is predicted in
strict privacy mode, where the log holds no paths or names to rebuild the checks from.

The built-in policy (`mohar_core::policy::BUILTIN`) is a fuller example: reads, docs, tests, code and
config edits, read-only shell commands, pushes to a branch and to the default branch.

After a crash, decisions without an outcome are rebuilt from the log on the next start and can still be
given one by `receipt_seq`; `call_id`s live only for the life of the process.

## `mohar approve <seq> --by <id> [--yes] [--daemon <url>]` and `mohar refuse ...`

Answer an escalation as one of the people it was routed to. The command reads it from the daemon
(`/v1/escalation`, which changes nothing) and prints the agent, the exact action, its SHA-256, who was
asked and the agent's record on that capability: its level and its verified passes and failures. It then
asks for confirmation, or answers straight away with `--yes`, and sends the hash of what it printed, so a
different action can't be answered by mistake. Exits 0 when the answer is recorded, 1 when the person
says no or the daemon refuses it (wrong person, already answered), and 2 when the daemon can't be reached.

```
$ mohar approve 41 --by user:lead-1
escalation 41
  agent    agent:claude-code/docs-writer
  action   Edit src/a.rs (fs.edit.code)
  args     sha256:c41b...
  hash     sha256:7e02...
  asked    user:lead-1
  record   level 0, 3 verified passes, 1 failure
approve this exact action as user:lead-1? [y/N]
```

## `mohar hook claude-code [--daemon <url>]`

The command Claude Code runs for `PreToolUse` and `PostToolUse`. It reads the hook payload on stdin, asks
the daemon, and prints Claude Code's `permissionDecision`: `allow`, `ask` (for `escalate`) or `deny`. It
denies when the daemon can't be reached, answers with an error, or the payload can't be read, and it only
ever talks to a loopback address. `PostToolUse` is recorded as a `host` outcome matched by `tool_use_id`.
Subagents are identified as `agent:claude-code/<agent_type>`, the main agent as `agent:claude-code/main`.
On `Stop` and `SubagentStop` it asks the daemon to verify the session's task, and reports the result on
stderr.
