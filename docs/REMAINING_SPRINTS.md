# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 59

Sprints 0–59 are complete, including repository/image/SBOM scanning, policy and baselines, service/history/reporting, AWS ECR discovery/scanning, web UI, Nmap/Nuclei network assessment, authenticated Linux posture/package/CVE scanning, local accounts and encrypted SSH credentials, CISA KEV enrichment, FIRST EPSS enrichment, explainable KEV/EPSS-aware web prioritization, persistent first-class asset inventory with scan-history association, authenticated Windows posture/software assessment over strict key-only OpenSSH, a public product experience with Free/Professional account-plan foundations, deterministic CLI network-range assessment limited to 16 sequential literal IP/CIDR targets, bounded single-URL HTTP/HTTPS DAST with authenticated web/API submission and explicit authorization acknowledgement, a complementary pinned Grype image-vulnerability adapter with scanner-specific evidence and existing CycloneDX artifact integration, bounded read-only EC2 compute discovery/association for explicitly approved instance IDs, bounded ECS service/task-definition/container-image association for explicitly approved workloads, and tenant-isolated authenticated job/asset access with deterministic legacy migration.

## Current sprint

### Sprint 60 — Billing Provider and Enforced Subscription Lifecycle

Replace the Professional preview toggle with opt-in Stripe-hosted Checkout and Billing Portal, verified/idempotent webhook-driven subscription state, and server-enforced entitlement transitions. Free/local usage remains independent of Stripe and incurs no payment-provider calls when billing is unconfigured.

## Candidate remaining sprints

### Sprint 61 — External Workflow Integrations

Add narrowly scoped outbound integrations such as GitHub issues, Jira, Slack, ServiceNow, or SIEM export. Each integration should be split further if required to preserve least privilege and a focused sprint boundary.

### Sprint 62 — Signed Policy and Governance Bundles

Add integrity/authenticity controls for shared policy bundles, controlled distribution, version/provenance evidence, and enterprise governance workflows.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- multi-user tenant membership, invitations, tenant switching, and project-level authorization after the Sprint 59 account-tenant foundation
- per-tenant API keys or external identity/OIDC before any production SaaS exposure
- tenant-aware sharing/ownership for SSH credentials and cloud discovery configuration
- production secret-manager integration for Stripe and other service credentials before public SaaS deployment
- richer billing operations such as invoice history, refunds/credits, taxes, coupons, metering, and billing-admin delegation
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
