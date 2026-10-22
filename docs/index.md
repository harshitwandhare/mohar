# Mohar documentation

Mohar is an open-source trust layer for AI agents. It records every agent action as a signed,
hash-chained receipt, lets an agent earn permission one capability at a time from outcomes that were
actually checked, takes that permission away the moment a gated action fails, and sends only the actions
an agent hasn't earned to a person.

!!! note "Status"
    Mohar is early. The receipt log and the `mohar` CLI are released (0.1). The trust engine, the
    escalation flow and the host adapters are designed and in progress; the
    [roadmap](ROADMAP.md) and its milestones say exactly what exists.

## Start here

- **[Install and first log](getting-started.md)**: install `mohar`, record decisions, verify the chain,
  and see what happens when someone edits or truncates it.
- **[CLI reference](cli.md)**: every command and flag.
- **[Design](design.md)**: capabilities, trust levels and the rules that move them, verification,
  escalation, receipts, privacy and the threat model.
- **[Receipts and checkpoints](formats.md)**: the formats, with test vectors and an independent checker.
- **[Integrations](integrations.md)**: how Mohar plugs into Claude Code, Codex, CAO, ADK, MCP and A2A,
  and how strong each seam is.
- **[Compliance](compliance.md)**: how Mohar maps onto HIPAA, GDPR, SOC 2, ISO 27001 and 42001 and the
  EU AI Act, control by control.

## Versions

These docs are versioned. The selector at the top switches between `latest` (the newest release), each
release, and `dev` (the `main` branch). Docs for a release never change after it ships.
