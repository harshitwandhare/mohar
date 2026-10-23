# Roadmap

Dates are targets. Each phase is a GitHub milestone, and every task in it is an issue with "Done when"
criteria: see [milestones](https://github.com/harshitwandhare/mohar/milestones). Everything built is held
to the [engineering bar](engineering-bar.md). Each phase ships as small pull requests against issues that say what
"done" means.

## Phase 0: foundation (Oct to Nov 2026), done

- Repository standards: CI, security scanning, contribution rules for humans and agents.
- Landing page and docs site.
- Design notes for the receipt format, the trust model and the escalation flow.

## Phase 1: receipts (Nov to Dec 2026), done

- Rust core: Ed25519 keys, a hash-chained append-only log, signed receipts for each action.
- `mohar` CLI: `init`, `log`, `verify`.
- Test vectors other implementations can run.

## Phase 2: first host, Claude Code (Dec 2026 to Jan 2027)

- Hook adapter that records every tool call and its result.
- Outcome verifiers: test runs and git diffs.

## Phase 3: trust per capability (Jan to Mar 2027)

- Capability taxonomy, per-capability scores, hard veto gates, and demotion in proportion to what a
  failure could have cost, with remediation plans and lessons the agent is given next time.
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
- One `mohar-hook` binary with profiles for Codex, Copilot, Cursor, Antigravity CLI and other hosts,
  each set to fail closed, and a CI check that refuses agent commits without verifying receipts.
- Agent contributors on open-source repos: start untrusted, earn rights through merged, verified work.

## Phase 7: enterprise (alongside Phases 4 to 6)

- Auditor evidence pack: an offline-verifiable export with control mappings and configurable retention.
- Approver protections: two-person approval, independent reinstatement after serious failures, escalation
  budgets and batching.
- Cost per verified outcome by agent, person and team, from the hosts' own cost telemetry.

## Not planned

- Another identity provider, policy language, orchestrator or memory store. Good ones exist; Mohar
  connects to them.
