# Roadmap

Dates are targets. Each phase ships as small pull requests against issues that say what
"done" means.

## Phase 0: foundation (Oct to Nov 2026)

- Repository standards: CI, security scanning, contribution rules for humans and agents.
- Landing page and docs site.
- Design notes for the receipt format, the trust model and the escalation flow.

## Phase 1: receipts (Nov to Dec 2026)

- Rust core: Ed25519 keys, a hash-chained append-only log, signed receipts for each action.
- `mohar` CLI: `init`, `log`, `verify`.
- Test vectors other implementations can run.

## Phase 2: first host, Claude Code (Dec 2026 to Jan 2027)

- Hook adapter that records every tool call and its result.
- Outcome verifiers: test runs and git diffs.

## Phase 3: trust per capability (Jan to Mar 2027)

- Capability taxonomy, per-capability scores, hard veto gates, instant demotion.
- Promotion only from verified outcomes, over a minimum window.

## Phase 4: escalation (Mar to May 2027)

- Route out-of-bounds actions to the right person.
- A small per-person model of past yes/no decisions, allowed only to skip prompts on low-risk, reversible
  actions inside limits that person set.

## Phase 5: benchmark (May to Aug 2027)

- Public, reproducible benchmark: false promotion rate, time to demotion, prompts avoided at a fixed
  incident rate, poisoning reaching durable memory.
- Write-up of methods and results.

## Phase 6: integrations (Aug 2027 onward)

- MCP proxy, CAO, Google ADK, Microsoft Agent Governance Toolkit, Paperclip.
- Agent contributors on open-source repos: start untrusted, earn rights through merged, verified work.

## Not planned

- Another identity provider, policy language, orchestrator or memory store. Good ones exist; Mohar
  connects to them.
