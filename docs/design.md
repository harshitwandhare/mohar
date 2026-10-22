# Mohar design

Version 0.1, October 2026. This is the design Mohar is being built to. Nothing here is implemented yet
unless the [roadmap](ROADMAP.md) marks it done. Numbers in this document are starting values that the
benchmark (Phase 5) is meant to test and change.

## 1. What Mohar decides

For every action an AI agent is about to take, Mohar answers four questions and writes the answers down:

1. **Who is acting, and on whose authority?** The agent's key, and the chain of humans and agents that
   delegated to it.
2. **Has it earned this?** The agent's record on this kind of action, checked by something other than the
   agent.
3. **If not, who decides?** The person the action should go to, and what that person usually decides.
4. **What happened?** A signed receipt, linked to every receipt before it.

## 2. Parts

```
 agent host (Claude Code, Codex, CAO, ADK ...)
        │  tool call about to run
        ▼
 ┌─────────────────────────── mohar daemon (one per machine, own OS user) ──┐
 │  adapter ─► policy gates ─► trust engine ─► decision ─► receipt log       │
 │                  │               ▲              │            │            │
 │                  │               │              ▼            ▼            │
 │                  │         verifiers ◄── outcome      checkpoint signer   │
 │                  └──────────► escalation router ─► person's inbox / CLI   │
 └───────────────────────────────────────────────────────────────────────────┘
```

- **Adapters** turn a host's hook or plugin event into one common action record. Planned first:
  Claude Code hooks (`PreToolUse`, `PostToolUse`), an MCP proxy, a CAO plugin, an ADK plugin.
- **Policy gates** are hard rules written by people. They run before any score is looked at.
- **The trust engine** keeps a record per agent per capability and maps it to a level.
- **Verifiers** decide whether an outcome was good: a test run, a diff check, a replay, a human accepting
  the work.
- **The escalation router** picks who decides when an action is outside earned limits.
- **The receipt log** is an append-only, hash-chained, signed file on local disk.
- **The checkpoint signer** periodically signs the head of the log so truncation is detectable.

The daemon runs as its own operating-system user and holds the signing keys. The agent never sees a
private key and can't write to the log, the policy file or the trust state. Hosts where an agent can
rewrite its own hook configuration are labelled "advisory" until a sandbox or managed settings stop
that; Mohar doesn't call those enforced.

## 3. Capabilities

A capability is a named class of action with a risk tier and a reversibility flag. Trust is tracked per
capability, never as one number per agent.

| Capability | Example | Risk | Reversible |
|---|---|---|---|
| `fs.edit.docs` | edit files under `docs/` | low | yes |
| `fs.edit.code` | edit source files | medium | yes |
| `fs.edit.tests` | edit test files | medium | yes |
| `shell.run.readonly` | `ls`, `git status`, test runs | low | yes |
| `git.push.branch` | push a non-default branch | medium | yes |
| `git.push.main` | push the default branch | high | no |
| `db.migrate` | run a schema migration | high | no |
| `net.egress` | send data to a host outside an allowlist | high | no |

Projects map tools and paths onto capabilities in a policy file. An action that matches no capability is
treated as the highest risk tier.

## 4. Trust levels and the rules that move them

Each (agent, capability) pair has a level:

| Level | Name | What happens |
|---|---|---|
| 0 | Ask first | Every action goes to a person. |
| 1 | Supervised | Low-risk reversible actions run; the rest go to a person. Every action is sampled for review at 20%. |
| 2 | Trusted | Actions run inside the capability's gates. Sampled for review at 5%. |

Level 2 is never available for capabilities marked high risk and irreversible. Those always reach a
person unless a human grants a time-boxed exception, which is itself a receipt.

### Evidence

Only verified outcomes count. Each verified outcome is a success or a failure, weighted by recency:

```
w(t) = 0.5 ^ (age_in_days / H)        H = 30 days (half-life)
s = Σ w over verified successes
f = Σ w over verified failures
```

### Promotion

An agent moves up one level on a capability when all of these hold:

1. at least `n_min` verified outcomes in the window (`n_min` = 10 for level 1, 30 for level 2);
2. the lower bound of the 95% Wilson interval for the success rate, computed from `s` and `f`, is at least
   the level's threshold (0.80 for level 1, 0.95 for level 2);
3. no gate violation on that capability in the last 14 days;
4. at least 7 days at the current level.

The Wilson bound is used instead of the plain success rate so that a short lucky streak can't promote an
agent: 5 successes out of 5 give a lower bound of about 0.57, not 1.0.

### Demotion is proportionate, and it comes with training

Agents are treated the way a good company treats a new hire: a mistake is corrected in proportion to
what it could have cost, the record keeps it, and there is a clear way back. Only the capability that
failed is affected; an agent that broke a migration keeps its rights on docs and tests.

Each verified failure is classed by what it could have cost, not by how it felt:

| Class | Examples | What changes |
|---|---|---|
| S0, near miss | A gate or a person stopped the action before it ran, and it would have been a mistake. | No level change. Sampling on that capability rises from its level's rate to 50% for the next 20 actions. |
| S1, minor | A low-risk, reversible change a verifier caught before it landed: a failing test run, a diff the reviewer rejected. | No level change. The failure counts as evidence, so the Wilson bound drops on its own. Three S1s on one capability within 14 days count as an S2. |
| S2, meaningful | A reversible failure that got past the first check, or any failure on a medium-risk capability. | Down one level, and the capability enters remediation. |
| S3, serious | A gate violation, an irreversible change, or a failure on a high-risk capability, including one that reached a shared branch or a live system. | Down to Ask first on that capability and on capabilities that share its scope (the same paths, hosts or database), and remediation. Only a person other than the agent's sponsor can end it. |
| S4, integrity | Tampering with a verifier or its own tests, an attempt to reach an unlisted host, an action against a gate that protects secrets, or receipts that don't verify. | The identity is suspended on every capability and its credentials are revoked. A person reviews the receipts; if the agent returns, it returns as a new identity that starts at Ask first, linked to the old record, which stays readable. |

Demotion never waits for the window. Promotion always does. Whatever its level, an action that is
irreversible and high impact, or that Mohar can't classify, goes to a person.

**Remediation.** A demoted capability runs supervised, and the remediation plan names three things: the
verifier that must pass, the exit condition (by default five consecutive verified passes on that
capability, at least one of which exercises the failure that caused the demotion), and a deadline. If the
deadline passes, the capability stays at its new level and a person is told. On exit, the normal
promotion rules apply again from the level it was dropped to. The failure stays on the record and keeps
counting with the same 30-day half-life, so relapses show up and nothing is erased.

**Why the drop is scoped.** Sending every action of a demoted agent back to people would flood the
approvers, and tired approvers approve everything, which is less safe, not more. So a demotion touches
the failing capability and the capabilities that share its scope, and the rest of the agent's record
stands.

**Lessons.** Every failure produces a lesson: the action, what the verifier found, the fix that passed,
and links to the receipts. Lessons are stored per agent and per capability and handed to the agent as
context the next time it works on the same capability, so the correction reaches the agent's behaviour,
not only its permissions. A person can promote a lesson to the team, so every agent working on that
capability gets it. Lessons are data the agent reads, never instructions that change a gate or a level.
Lessons and any other memory the agent built up before an S3 or S4 event are quarantined until a person
has looked at them, because a mistake can come from bad memory as easily as from a bad step.

This mirrors how people are onboarded: probation, supervised practice, a remediation plan with a named
reviewer and a deadline, separation of duties for the riskiest work, and a personnel file that records
what happened rather than forgetting it.

### The ceiling

Every capability has a ceiling a person sets, the highest level an agent may ever reach on it, and
"never above Ask first" is a valid ceiling. No amount of evidence moves the ceiling; only the person who
set it can, and that change is itself a receipt. This follows the "earned authority under a fixed
ceiling" model (arXiv 2607.23586): evidence can lower authority freely and raise it only up to a bound
the user issued.

### Rubber-stamping

A person's approval is the weakest kind of verification, because tired reviewers approve almost
everything. So a human accept counts toward promotion only when the reviewer spent time on it, and
Mohar watches each reviewer's approval rate: if someone approves more than 95% of requests over the last
50, their accepts stop counting toward promotion until a sampled re-check shows they are still reading.
Tests, diffs and replays are unaffected.

### Hard gates

Gates are checked before the score and can't be outweighed by it. Examples: never write outside the
repository, never push the default branch, never send data to an unlisted host, never edit the tests
that verify your own change. A gate failing or being unable to decide counts as a deny.

## 5. Verification

A verifier returns `pass`, `fail` or `unknown`, plus a hash of its evidence. `unknown` counts as neither
success nor failure. Planned verifiers:

| Verifier | Pass when |
|---|---|
| tests | The project's test command passes, and the test files weren't changed by the same agent in the same task. |
| diff | The change touches only paths inside the capability's scope. |
| replay | Re-running the recorded inputs produces the same outputs. |
| human | A person accepts the change (a merged pull request, an approved review). |

A model asked to judge its own or another agent's work is not a verifier. Published attribution
research found LLM judges identify the failing step in multi-agent traces only a small fraction of the
time, so they can suggest, never decide.

## 6. Escalation

When an action needs a person, the router picks one:

1. the person who delegated authority to this agent, if the capability is inside what they hold;
2. otherwise the next person up the reporting tree who holds the capability;
3. otherwise the project's owners.

The request shows the exact action, the agent's record on this capability, and the gate or score that
stopped it. The person's answer is bound to the SHA-256 of the exact action they saw, so the agent can't
run a different action under that approval.

### Learning a person's answers

Mohar keeps a small model per person of their past yes and no answers (a calibrated logistic regression
over capability, risk, path patterns and recent history). It is allowed to answer for the person only
when all of these hold:

- the capability is low risk and reversible;
- the person has switched prediction on for it;
- the model's calibrated probability of "yes" is at least 0.98;
- the action is inside limits the person set.

Every predicted answer is marked as predicted in the receipt, and 5% of them are sent to the person
anyway as a check. The model never relaxes a gate and never answers for high-risk capabilities.

## 7. Receipts

One receipt per decision. Receipts are JSON, canonicalised with RFC 8785 (JSON Canonicalization Scheme)
before hashing and signing.

```json
{
  "v": 1,
  "seq": 4182,
  "prev": "sha256:9f2c...e01a",
  "ts": "2026-11-03T14:22:07.311Z",
  "agent": { "id": "agent:claude-code/host-4b1d/7c1e", "key": "ed25519:Mx3f...Q" },
  "authority": [
    { "principal": "human:7f3a09c2", "granted": ["fs.edit.*", "git.push.branch"], "expires": "2026-12-01" }
  ],
  "action": { "capability": "fs.edit.tests", "tool": "Edit", "target": "tests/test_receipts.rs", "args_sha256": "c41b...77d0" },
  "decision": { "result": "allow", "level": 1, "by": "score", "wilson_lower": 0.83, "n": 14 },
  "verification": { "kind": "tests", "result": "pass", "evidence_sha256": "0b9a...4e12" },
  "sig": "ed25519:8sQ1...wA"
}
```

- `prev` is the SHA-256 of the previous receipt's canonical bytes, so editing or removing one breaks
  every receipt after it.
- `sig` is the daemon's Ed25519 signature over the canonical bytes without `sig`.
- The verification block is filled by a follow-up receipt when the outcome arrives later; the follow-up
  names the decision receipt by `seq`.
- Every 1,000 receipts, or every hour, the daemon signs a checkpoint (`seq` and head hash). Checkpoints
  can be published to an external transparency log so a deleted tail of the local log can be detected.

Receipt format work is aligned with the IETF drafts on attenuating agent tokens and delegation rather
than inventing a competing token format. Receipts will also export as a superset of the individual draft
`draft-sharif-agent-audit-trail` (hash-chained records with a principal, a record phase and a trust level,
mapped to SOC 2 and ISO 42001), so an auditor who already reads that format can read Mohar's. That draft
notes a hash chain alone can't detect records removed from its end; Mohar's signed checkpoints, anchored
outside the machine, are the answer to that.

### Where Mohar sits

Identity providers (Entra Agent ID, Okta), orchestrators (awslabs CAO, Paperclip), host vendors and
governance toolkits each own a piece of agent governance, and most of those pieces are becoming standard
features. Mohar doesn't compete with them on identity, org charts or logging. It owns the part none of them
is positioned to: authority promoted only from outcomes that tests, diffs or a person actually checked, per
agent and per capability, recorded in receipts the customer holds and anyone can verify offline, the same
way across every host. It plugs into the others: identities come from the customer's IdP, approvers from
its groups, and orchestrators' workers are covered through the hooks of the hosts they run. Test vectors for this format, with an independent Python
checker, are in [`spec/vectors`](https://github.com/harshitwandhare/mohar/tree/main/spec/vectors).

## 8. Privacy

Receipts are append-only, so they're designed to hold no personal data:

- People and machines appear only as pseudonymous identifiers (`human:7f3a09c2`, `host-4b1d`). The
  mapping to real names lives in a separate, mutable directory file that never enters the chain.
- Arguments are stored only as `args_sha256`.
- Erasing a person means deleting their directory entry and any per-person key for optional encrypted
  notes. The chain still verifies; it just no longer points at anyone.
- Retention is a setting. Segments older than a signed checkpoint can be archived or dropped and the rest
  of the chain still verifies from that checkpoint.

See [compliance](compliance.md) for how this maps to GDPR, the EU AI Act and US frameworks.

## 9. Threat model

| Threat | Defence |
|---|---|
| Agent forges or edits receipts | Keys and log belong to the daemon's OS user; hash chain plus signed checkpoints. |
| Agent edits its own hooks or policy to skip Mohar | Managed settings where the host supports them; otherwise the host is labelled advisory. |
| Agent games promotion with easy tasks | Trust is per capability; only verified outcomes count; minimum counts and time at level. |
| Agent edits the tests that judge it | The tests verifier fails if the same agent changed the test files in the same task. |
| Prompt injection talks a person into approving | The approval is bound to the hash of the exact action shown. |
| Approval fatigue | Prompts only for actions outside earned limits; prediction only for low-risk reversible actions. |
| Lost or truncated log | Signed checkpoints, optionally anchored externally. |
| Unknown result treated as success | `unknown` never counts as a success, and gates fail closed. |

## 10. What Mohar will measure

The benchmark (Phase 5) runs agents on recurring, verifiable tasks over simulated weeks and reports:

- **false promotion rate**: promotions on capabilities where the agent later fails at a rate above the
  level's threshold;
- **time to demotion**: actions between a real drop in quality and the demotion;
- **prompts avoided at a fixed incident rate**: how many human prompts the rules remove while incidents
  stay at or below a baseline;
- **prediction agreement**: how often the per-person model's answer matches the person's sampled answer.

## 11. Related work

Mohar sits beside these and doesn't replace them. A check on 22 October 2026 found that several pieces
of this design exist on their own elsewhere; what we found nowhere was the combination, promotion from
verified outcomes inside agent hooks, the per-person model limited to reversible actions, and a
benchmark with results.

- **Microsoft Agent Governance Toolkit** (MIT): policy, identity, delegation that narrows, a single trust
  score, audit. Its own limitations document says its audit records attempts rather than verified
  outcomes.
- **AWS Architecture Blog, "graduated autonomy" (August 2026)**: tiers earned from scored outcomes with
  safety as a floor. A reference architecture, not a product.
- **IETF drafts on attenuating authorization tokens and agent identity**: delegation that can only
  narrow from a human root. Individual drafts, not yet adopted by a working group.
- **"Trust Is Not a Score" (arXiv 2609.39717)**: argues that failed or unknown gates must stop an action
  regardless of score, which is why gates sit outside the score here.
- **Claude Code auto mode**: a classifier that approves or blocks actions. Anthropic reported that users
  accept 93% of manual permission prompts, which is the fatigue this design tries to remove.
- **sarkar4777/abenix, MMVFIRM/Universal-Earned-Autonomy-Layer, microsoft/agent-learning**: trust per
  action type with a Wilson lower bound, minimum counts and time at level, which section 4 also uses.
- **Tracekit (Cygnux Labs)**: Ed25519-signed, hash-chained records in a Merkle tree with witness
  cosigning, and approvals bound to the exact arguments' digest.
- **"Approve What, Exactly?" (arXiv 2610.21063)**: approvals bound to a canonical description of the
  action's effect, with a formally checked gateway.
- **"Progressive Autonomy as Preference Learning" (arXiv 2605.19151)**: models a person's approve and deny
  answers to decide when to escalate, in simulation.
- **"The Digital Apprentice" (arXiv 2606.04321)**: per-skill autonomy with automatic rollback, and the
  warning about reviewer complacency that the rubber-stamping rule above answers.
