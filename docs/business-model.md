# How Mohar is meant to sustain itself

Mohar is a non-commercial open-source project today. Nothing is sold, there are no paid plans, and no
money is accepted. This page sets out how a sustainable model could work later, so that the open-source
decisions made now don't close it off.

## What stays free, always

Everything a single developer or a single team needs to run Mohar on their own machines:

- the daemon, the CLI and the receipt log;
- every adapter and plugin (Claude Code, Codex, CAO, ADK, MCP and the rest);
- the trust engine, verifiers and escalation;
- the benchmark and its data.

All of it is Apache-2.0, including the right to run it commercially. The name "Mohar" is the only thing
not covered by the license.

## Where value could be charged for, later

The model that works for infrastructure like this, used by companies such as Grafana, PostHog, Sentry
and Supabase, is a free core with paid help for organisations operating it at scale. For Mohar that would
mean:

| Offering | Who needs it | Why it isn't in the free core |
|---|---|---|
| A hosted service for teams: shared receipt storage, cross-machine trust, an approvals inbox | Teams of 10 or more running many agents | It's operating a service, not software |
| Org tree sync from the identity provider and HR system (Okta, Entra, Google Workspace) | Companies with more than a few hundred people | Connectors to enterprise systems need ongoing maintenance |
| Compliance exports mapped to the EU AI Act, SOC 2 and ISO 42001 | Regulated deployers | Each framework needs dated, maintained mappings |
| Support, security response commitments and long-term support releases | Enterprises | A service-level promise, not code |

## Partnerships before revenue

Integrations come before any of that, because a trust layer is only useful where agents already run:

1. **Upstream first.** Land the seams Mohar needs (for example pre-action veto events in CAO) as ordinary
   contributions to those projects, useful even without Mohar.
2. **Plugins in each project's own catalogue.** Claude Code plugins, ADK plugins, Microsoft Agent
   Governance Toolkit plugins.
3. **Standards work.** Test vectors and reference code for the IETF delegation drafts and A2A, rather
   than a competing format.

## What would trigger a company

A company would be formed only when all three hold: people outside the project depend on Mohar in
production, at least a few organisations ask for something in the paid column above, and the maintainer
is in a position to run a company properly. Until then the project takes no sponsorships, bounties or
grants.
