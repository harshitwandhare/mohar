# Compliance

Last reviewed: 22 October 2026. This is an engineering map of the US and EU rules that touch Mohar,
written so the design meets them from the start. It isn't legal advice. Anyone deploying Mohar in a
regulated setting should have counsel confirm how these rules apply to them.

Two different questions run through this page:

- **Rules on the project.** What applies to Mohar itself, as open-source software published by an
  individual with no revenue.
- **Rules on the people who use it.** What Mohar's users have to prove, and how Mohar's receipts help
  them prove it.

## Summary

| Rule | Applies to the project now? | How Mohar helps users |
|---|---|---|
| EU AI Act | No. Mohar records and gates other systems' actions; it isn't itself a high-risk AI system. | Automatic, lifetime event logs (Article 12) and human oversight (Article 14) for the agents it governs. |
| GDPR (EU) and CCPA (California) | Only for the project's own website, which collects no personal data. | Pseudonymous receipts, no raw arguments, erasure by key destruction, configurable retention. |
| EU Cyber Resilience Act | Not as a manufacturer while it's non-commercial open source. Would apply if a company sells it. | A documented vulnerability process and SBOMs from day one, so the move to manufacturer duties is small. |
| NIS2 and DORA (EU) | No. | Tamper-evident records of who changed what in critical systems. |
| US export controls (EAR) | Checked: publicly available source using standard cryptography is not subject to the EAR. | Not applicable. |
| NIST AI RMF, NIST SP 800-53 (US) | Voluntary frameworks. | Evidence for audit and accountability controls. |
| SOC 2, ISO/IEC 27001, ISO/IEC 42001 | Certifications for organisations, not code. | Evidence for logging, change management and AI governance controls. |
| HIPAA (US) | No. | Audit controls for systems that touch health data. |

## EU AI Act

The Digital Omnibus on AI, Regulation (EU) 2026/1744, in force since 27 July 2026, moved the high-risk
obligations: stand-alone high-risk systems listed in Annex III now apply from **2 December 2027**, and
AI that is a safety component of regulated products (Annex I) from **2 August 2028**.

What Mohar's receipts are built to support:

- **Article 12, record-keeping.** High-risk systems must "technically allow for the automatic recording
  of events (logs) over the lifetime of the system", with logs that help identify risk, support
  post-market monitoring and monitor operation. Every Mohar decision is logged automatically, chained,
  and signed, so a deployer can show the log is complete and unaltered.
- **Article 14, human oversight.** People must be able to understand, override and stop the system.
  Escalation sends out-of-bounds actions to a named person, the approval is bound to the exact action,
  and the person's identity is in the receipt.

Mohar doesn't make an agent compliant on its own. It gives the deployer the records and controls the Act
asks for.

## GDPR and US state privacy laws

An append-only log and a right to erasure (GDPR Article 17) pull in opposite directions. Mohar resolves
this in the design rather than later:

1. **No personal data in the chained fields.** Receipts identify people and agents by pseudonymous
   identifiers (`human:7f3a...`), never by name or email. The mapping from identifier to person lives in a
   separate, mutable directory file.
2. **Arguments are hashed, never stored.** `args_sha256` proves which action was approved without keeping
   its contents.
3. **Erasure by destroying the mapping.** Deleting a person's directory entry, and any per-person key
   used to encrypt optional notes, leaves the chain verifiable but no longer linked to that person. This
   approach (often called crypto-shredding) is the common answer for immutable logs; whether it fully
   satisfies Article 17 hasn't been settled by regulators, so deployers should confirm with their DPO.
4. **Retention is a setting.** Old segments can be archived or dropped after a signed checkpoint, so the
   remaining chain still verifies from that checkpoint.
5. **Local by default.** The log lives on the deployer's machine. Nothing is sent to the project.

The project website sets no cookies, runs no analytics and collects nothing.

## EU Cyber Resilience Act

Manufacturers must report actively exploited vulnerabilities from **11 September 2026**, and the full
product requirements apply from **11 December 2027**. Free open-source software that isn't placed on the
market in a commercial activity falls outside manufacturer obligations. An organisation that sells or
monetises Mohar later would become a manufacturer for that product.

Already in place, so that move is small:

- a security policy with private vulnerability reporting (SECURITY.md);
- automated secret scanning, CodeQL and dependency updates;
- planned for the first release: a software bill of materials and signed build provenance for every
  artefact.

## US export controls

Under 15 CFR 742.15(b), publicly available encryption source code is not subject to the EAR. A
notification to BIS and the NSA is required only for code that performs non-standard cryptography.
Mohar uses only standard, published algorithms (Ed25519, SHA-256), so no notification applies. Any
change that adds a non-standard cryptographic algorithm must revisit this.

## Frameworks the receipts map onto

| Framework | Controls the receipts give evidence for |
|---|---|
| NIST SP 800-53 | AU family: event logging, audit record content, protection of audit information, non-repudiation (AU-10). |
| NIST AI RMF | Govern and Manage functions: accountability for AI actions, human oversight, incident tracking. |
| SOC 2 | Change management and monitoring of system components. |
| ISO/IEC 27001 | Logging and monitoring controls. |
| ISO/IEC 42001 | AI management system: oversight, traceability and records of AI system operation. |
| HIPAA | Audit controls for systems that handle electronic protected health information (45 CFR 164.312(b)). |

## Open questions for counsel

- Does crypto-shredding of the identity mapping satisfy GDPR Article 17 for a given deployment?
- When a company is formed and offers a paid tier, which CRA conformity route applies?
- For AI Act Annex III deployments, which minimum log retention applies to the deployer, and does it
  conflict with a shorter privacy retention setting?

## Sources

- Regulation (EU) 2026/1744 (Digital Omnibus on AI): [AI Act Explorer](https://artificialintelligenceact.eu/ai-act-explorer/digital-omnibus/), [Orrick](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes)
- AI Act Article 12: [AI Act Explorer](https://artificialintelligenceact.eu/article/12/)
- Cyber Resilience Act timeline and open-source stewards: [OpenSSF](https://policy.openssf.org/CRA/stewards-one-pager.html), [Goodwin](https://www.goodwinlaw.com/en/insights/publications/2026/09/alerts-lifesciences-technology-preparing-for-eu-cyber-resilience-act)
- GDPR and immutable records: [EDPB Guidelines 02/2025 summary](https://www.mondaq.com/fin-tech/1617044/blockchain-and-gdpr-edpb-guidelines-022025-adopted)
- US export controls: [15 CFR 742.15](https://www.law.cornell.edu/cfr/text/15/742.15)
