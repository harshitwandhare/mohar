<p align="center"><img src="site/assets/brand/mohar-seal-512.png" alt="The Mohar seal: मो in Modi script on a gold octagonal medallion" width="160"></p>

<h1 align="center">Mohar</h1>

<p align="center">Agents should earn what they're allowed to do, and lose it in proportion to what they get wrong.</p>

<p align="center">
  <a href="https://github.com/harshitwandhare/mohar/actions/workflows/rust.yml"><img alt="Rust" src="https://github.com/harshitwandhare/mohar/actions/workflows/rust.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/harshitwandhare/mohar/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/harshitwandhare/mohar/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/harshitwandhare/mohar/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/harshitwandhare/mohar"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/harshitwandhare/mohar"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/harshitwandhare/mohar/badge"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

<p align="center">
  <a href="https://mohar-liard.vercel.app">Website</a> ·
  <a href="https://harshitwandhare.github.io/mohar/">Docs</a> ·
  <a href="https://harshitwandhare.github.io/mohar/latest/getting-started/">Install</a> ·
  <a href="docs/design.md">Design</a> ·
  <a href="docs/ROADMAP.md">Roadmap</a>
</p>

Mohar is an open-source trust layer for AI agents. It watches what an agent does, checks whether the
result was actually right, and turns that record into permission: an agent that keeps passing your tests
on a kind of task stops asking you about it, and an agent that breaks something loses that right straight
away. Every decision leaves a signed receipt.

## Status

Mohar is early, and this table is kept honest.

| Piece | State |
|---|---|
| Signed, hash-chained receipt log (`mohar-core`) | Released in 0.1 |
| `mohar` CLI: `init`, `append`, `log`, `checkpoint`, `verify` | Released in 0.1, for Linux, macOS and Windows |
| Receipt format test vectors, with an independent Python checker | Released in 0.1 |
| Trust engine, verifiers, escalation, host adapters | Designed in [docs/design.md](docs/design.md), being built ([roadmap](docs/ROADMAP.md)) |

Nothing here is production-ready yet.

## Why

Coding agents already run with real permissions on real machines. The ways we limit them today are
blunt:

- **Static allowlists.** The same rule applies on day one and on day five hundred, no matter how the
  agent has behaved.
- **Prompts asking the model to behave.** Some orchestrators enforce tool limits only by telling the
  model what it may not do.
- **Approval prompts for everything.** People stop reading them. In March 2026 Anthropic wrote that users
  accept 93% of Claude Code's manual permission prompts.
- **One trust score per agent.** Being good at editing docs says nothing about being safe with
  database migrations, and an average can hide a failure that should have been a hard stop.

Mohar ties an agent's authority to its verified record, one capability at a time.

## How it works

Mohar runs beside the tools you already use. It doesn't replace your orchestrator, your identity
provider or your policy engine.

1. **Record.** Each action an agent takes is written to a local, hash-chained log and signed.
2. **Verify.** The outcome is checked by something that doesn't guess: tests, a diff review, a replay,
   or a human accepting the work. A model's opinion of itself never counts as verification.
3. **Score per capability.** Trust is tracked separately for each kind of action (edit tests, run
   migrations, push to a branch), with hard gates that no score can average away.
4. **Decide.** Inside earned limits, the action runs. Outside them, it goes to the right person, along
   with what the agent has done before and what that person usually decides. One failure on a gated
   capability demotes the agent immediately.

## Install

Each [release](https://github.com/harshitwandhare/mohar/releases) has builds for Linux and macOS (x86_64
and arm64) and Windows (x86_64), with checksums and GitHub build attestations.

```bash
# Linux and macOS
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/harshitwandhare/mohar/releases/latest/download/mohar-cli-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/harshitwandhare/mohar/releases/latest/download/mohar-cli-installer.ps1 | iex"
```

To check that a download was built by this repository's release workflow:

```bash
gh attestation verify mohar-cli-x86_64-unknown-linux-gnu.tar.xz -R harshitwandhare/mohar
```

## Try it

```bash
mohar init
mohar append --agent agent:me/1 --capability fs.edit.docs --tool Edit \
  --target docs/a.md --args-sha256 c41b77d0 --result allow --level 1 --by score
mohar checkpoint
mohar verify
# ok: 1 receipts and 1 checkpoints verified
```

Edit any line in `.mohar/receipts.jsonl` and `verify` names the receipt that broke. Delete lines from the
end after a checkpoint and `verify` reports how many receipts are missing. The
[getting started guide](https://harshitwandhare.github.io/mohar/latest/getting-started/) walks through
both.

## What's planned to plug into

Claude Code hooks, MCP servers through a proxy, awslabs/cli-agent-orchestrator, Google ADK, Microsoft's
Agent Governance Toolkit, and Paperclip. [Integrations](docs/integrations.md) says how strong each seam
is.

## Repository

| Path | What it holds |
|---|---|
| `crates/mohar-core` | Receipts, signing, verification and the on-disk log |
| `crates/mohar-cli` | The `mohar` command |
| `spec/vectors` | Format test vectors and the independent checker |
| `docs` | Design, roadmap, compliance, engineering bar; published as the docs site |
| `site` | The website |

Every pull request runs tests on Linux, macOS and Windows, a 95% line coverage floor, cargo-deny, CodeQL,
gitleaks, zizmor, and browser tests in Chromium, Firefox, WebKit and a phone profile. The standard each part is held to is in
[docs/engineering-bar.md](docs/engineering-bar.md).

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Please don't open a public
issue for them.

## Contributing

Humans and coding agents are both welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), and if you're
an agent, read [AGENTS.md](AGENTS.md) first.

## License

Apache-2.0. See [LICENSE](LICENSE). "Mohar" is the project's name and isn't licensed for use as the
name of other products.

## The name

Mohar (मोहर) is the Marathi word for a seal or stamp, the mark that makes a record count. The logo is a
seal stamp drawn after 17th-century Deccani gilt-brass finials: a scaled lotus bud, a beaded collar, an
ogee-lattice shaft and an octagonal die.
