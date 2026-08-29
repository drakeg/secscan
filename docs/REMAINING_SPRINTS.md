# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 57

Sprints 0–57 are complete, including repository/image/SBOM scanning, policy and baselines, service/history/reporting, AWS ECR discovery/scanning, web UI, Nmap/Nuclei network assessment, authenticated Linux posture/package/CVE scanning, local accounts and encrypted SSH credentials, CISA KEV enrichment, FIRST EPSS enrichment, explainable KEV/EPSS-aware web prioritization, persistent first-class asset inventory with scan-history association, authenticated Windows posture/software assessment over strict key-only OpenSSH, a public product experience with Free/Professional account-plan foundations, deterministic CLI network-range assessment limited to 16 sequential literal IP/CIDR targets, bounded single-URL HTTP/HTTPS DAST with authenticated web/API submission and explicit authorization acknowledgement, a complementary pinned Grype image-vulnerability adapter with scanner-specific evidence and existing CycloneDX artifact integration, and bounded read-only EC2 compute discovery/association for explicitly approved instance IDs.

## Current sprint

### Sprint 58 — Bounded ECS Workload Association

Associate explicitly approved ECS services with their task definitions and container image references using read-only AWS metadata. Promote only immutable `@sha256` image references as exact secscan association targets. Do not enumerate clusters/services/tasks, mutate ECS resources, trigger scans, or enable paid AWS security services.

## Candidate remaining sprints

### Sprint 59 — Tenant and Authorization Isolation

Evolve the existing local multi-user account foundation into explicit tenant/project ownership, role-scoped assets and scans, and storage/API isolation suitable for a future SaaS deployment.

### Sprint 60 — Billing Provider and Enforced Subscription Lifecycle

Integrate a real billing provider only after tenant/account ownership is ready. Add checkout, verified webhook-driven subscription state, upgrade/downgrade/cancellation lifecycle, payment-failure handling, and explicit cost/provider-fee documentation. Never store raw payment-card data in secscan.

### Sprint 61 — External Workflow Integrations

Add narrowly scoped outbound integrations such as GitHub issues, Jira, Slack, ServiceNow, or SIEM export. Each integration should be split further if required to preserve least privilege and a focused sprint boundary.

### Sprint 62 — Signed Policy and Governance Bundles

Add integrity/authenticity controls for shared policy bundles, controlled distribution, version/provenance evidence, and enterprise governance workflows.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- EKS/Kubernetes workload association with explicit cluster/namespace/workload allow-lists and least-privilege RBAC
- authenticated web/API submission for the bounded `network-range` scanner with explicit authorization acknowledgement
- Windows web/API submission and reusable credential-profile workflow after the CLI scanner boundary is accepted
- richer remediation analytics and censored-aware timing metrics
- additional SBOM formats and complementary SBOM engines such as Syft where they add independent value
- deeper license/dependency governance
- private registry authentication beyond current GitHub/ECR paths
- expanded release signing/provenance controls
- cross-source vulnerability/inventory correlation
- automated but bounded reassessment scheduling after persistent assets exist
- additional cloud providers
- agent-based assessment only if a later threat/cost review justifies it
- legacy `ROADMAP.md` current-sprint consolidation; this file is authoritative for the active and candidate sprint sequence until that historical roadmap is normalized

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
