# Integrations

Mohar doesn't replace the tools agents already run in. It plugs into them at the point where a tool call
is about to happen, asks the local Mohar daemon for a decision, and records the result.

How strong that is depends on the host. This page labels each one honestly:

- **Enforced**: the host lets Mohar block the action and the agent can't switch it off from inside.
- **Blocking, bypassable**: Mohar can block, but an agent running as the same OS user could edit the
  configuration. Pair it with a sandbox or a separate OS user.
- **Advisory**: the host's hooks fail open on errors or timeouts, so Mohar records and warns but can't
  guarantee a block.

Status for every row: designed, not built. The roadmap puts Claude Code first (Phase 2) and the rest in
Phase 6.

## Coding agent hosts

| Host | Seam | Strength | Plan |
|---|---|---|---|
| **Claude Code** | Settings hooks: `PreToolUse` returns allow, deny or ask; `PermissionRequest`; `PostToolUse` for outcomes; `SubagentStart` for child agents. Hook events carry `agent_id` for subagents. | Enforced when delivered through managed settings with managed hooks only; blocking, bypassable as a user hook. | A plugin with `hooks.json` that calls the local daemon, distributed through managed settings for teams. |
| **OpenAI Codex** | `PreToolUse`, `PermissionRequest`, `PostToolUse` hooks; managed through `requirements.toml`. Its docs say hook errors and timeouts don't block the tool call. | Advisory. | Same daemon call, deployed through managed `requirements.toml`, run inside Codex's sandbox. |
| **awslabs/cli-agent-orchestrator (CAO)** | Event plugins today are observers only (`post_*` events, no veto). Because CAO launches the real Claude Code and Codex binaries, their hooks still apply inside CAO sessions. | Inherits the strength of the provider underneath. | Contribute `pre_*` events with veto upstream (CAO issue #671). Map CAO's terminal identity and allowlists onto Mohar capabilities so children narrow from their parent. |

## Agent frameworks

| Framework | Seam | Strength | Plan |
|---|---|---|---|
| **Google ADK** (Go, Python) | A global `Plugin` registered on the `Runner` with a before-tool callback; a non-empty return skips the tool. Applies to every agent and sub-agent on that runner. | Enforced inside the process. | One plugin package per language that calls the daemon over local HTTP. |
| **Microsoft Agent Framework** | Function middleware that can terminate or fail a tool call before it runs. | Enforced inside the process. | Middleware package. |
| **LangChain / LangGraph** | `AgentMiddleware.wrap_tool_call` can skip calling the tool. | Enforced inside the process. | Middleware package. |
| **CrewAI** | `pre_tool_call` hooks; a hook stops a call by raising `HookAborted`, but any other exception is swallowed. | Advisory unless the hook is written to fail closed. | Hook that converts every error into `HookAborted`. |

## Protocols

| Protocol | Seam | Plan |
|---|---|---|
| **MCP** | A proxy that sits between the agent and its MCP servers and sees every tool call. | `mohar mcp-proxy`: decide, record, then forward or refuse. Works with any MCP client. |
| **A2A** | Extensions plus client and executor interceptors. A2A 1.0 leaves the meaning of an authorization decision open (section 7.6.4). | Carry the delegation chain and the decision receipt as an A2A extension; contribute test vectors for signed AgentCards (A2A #2122). |

## Governance platforms

| Project | Relationship |
|---|---|
| **Microsoft Agent Governance Toolkit** | Its policy, identity and audit layers overlap Mohar's edges; its documented gaps (outcome verification, per-capability trust, routing to the right person) are Mohar's core. Plan: a Mohar plugin for its approval and trust interfaces, not a competing runtime. |
| **Paperclip** | Runs agents as an org chart with approvals. Plan: Mohar supplies earned, per-capability trust and verified outcomes behind Paperclip's approvals. |
| **Entire** | Records coding-agent sessions beside commits. Plan: read Entire checkpoints as evidence for the diff and replay verifiers. |
| **mitchellh/vouch** | Gates which humans may contribute to a repository. Plan: vouch-compatible agent identities that start untrusted and earn rights through merged, verified work. |

## The interface every adapter uses

Every adapter makes the same two calls to the daemon on the local machine:

```
POST /v1/decide   { agent, capability, tool, target, args_sha256 }  ->  { result, level, receipt_seq }
POST /v1/outcome  { receipt_seq, verifier, result, evidence_sha256 }  ->  { receipt_seq }
```

If the daemon can't be reached, adapters on enforcing hosts deny. That is the fail-closed rule from the
design.
