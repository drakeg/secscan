# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 60

Sprints 0–60 are complete, including the capabilities previously summarized here plus an opt-in tenant-bound Stripe Checkout, Billing Portal, verified webhook, and enforced subscription lifecycle that leaves unconfigured local Free usage independent of Stripe.

## Current sprint

### Sprint 61 — Bounded GitHub Issue Export

Prepare one deterministic, bounded issue from one completed local secscan report and submit it only with an explicit flag and narrowly scoped environment token. Offline preparation remains the default and no background integration service is introduced.

## Candidate remaining sprints

### Sprint 62 — Signed Policy and Governance Bundles

Add integrity/authenticity controls for shared policy bundles, controlled distribution, version/provenance evidence, and enterprise governance workflows.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- multi-user tenant membership, invitations, tenant switching, and project-level authorization after the Sprint 59 account-tenant foundation
- per-tenant API keys or external identity/OIDC before any production SaaS exposure
- tenant-aware sharing/ownership for SSH credentials and cloud discovery configuration
- production secret-manager integration for Stripe and other service credentials before public SaaS deployment
- richer billing operations such as invoice history, refunds/credits, taxes, coupons, metering, and billing-admin delegation
- additional outbound integrations such as Jira, Slack, ServiceNow, and SIEM export after the GitHub issue boundary is accepted
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

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
