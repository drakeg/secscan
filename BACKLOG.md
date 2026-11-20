# Secscan — Prioritized Backlog

An engineering-ready item includes the customer problem, safe scope, acceptance criteria, owner/reviewer, test evidence and rough cost impact. Track detailed milestones in `SPRINTS.md` and `docs/REMAINING_SPRINTS.md`.

| Priority | Item | Acceptance / user value | Status |
| --- | --- | --- | --- |
| P0 | Complete PR #223 tenant-partitioned inventory and #224 Grype update | Existing CI/CodeQL green; review and merge according to protections | Open, green checks at 2026-11-19 audit |
| P0 | Adopt Mad Mallard repo governance and verified badges | Root docs, accurate badges, validation in CI, no false license or release claims | In progress |
| P0 | Verified AWS discovery provenance | Same-tenant, authenticated source proof before report enrichment | Planned, Sprint 82 |
| P1 | SMB scan → triage → remediation report | Operator completes practical workflow without hand-editing JSON | Planned, Sprint 83 |
| P1 | First-run Docker Compose demo and LAN-safe documentation | Verified install, health endpoint, login and sample scan | Planned, Sprint 83 |
| P1 | Pilot with small MSP / web agency | Obtain actual workflow feedback and willingness-to-pay evidence | Planned, Sprint 84 |
| P1 | Decide open-source license | Explicit maintainer approval and compatible notice; no invented badge | Blocked on product/maintainer choice |
| P2 | Verified asset exposure / identity context | Evidence freshness and permissions reviewed before risk claims | Future |
| P2 | Cloud-hosted deployment | Only if security and costs are authorized; Docker Compose remains default | Future |

**Commercial hypothesis:** Small MSPs and web agencies benefit from consistent scan evidence and customer-facing remediation reports. Candidate pricing **for validation only**: $49–$149/month per agency for self-hosted multi-client reports, or a fixed-fee initial audit. No customers, revenue, price acceptance or market demand have been verified.

**Prioritization:** Security/CI failures supersede feature work; next focus is verified discovery provenance, followed by a complete demo, then pilot validation.
