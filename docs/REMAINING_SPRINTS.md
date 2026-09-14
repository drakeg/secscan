# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 70

Sprints 0–70 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, multi-user tenant membership with session-scoped tenant switching, owner-controlled expiring tenant invitations with authenticated single-use acceptance, and tenant-owned projects with validated optional scan-job association.

## Current sprint

### Sprint 71 — Project-Specific Member Access Control

Add an explicit project authorization layer inside the tenant boundary. Tenant owners administer viewer/operator access for same-tenant members; operators may submit project scans, viewers may read permitted project evidence, and unauthorized/cross-tenant access fails closed. Existing projects remain tenant-member accessible until an owner explicitly configures project membership so the migration does not silently revoke access.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 71 is accepted, reprioritize the remaining backlog before assigning Sprint 72.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- per-tenant API keys or external identity/OIDC before any production SaaS exposure
- tenant-aware sharing/ownership for cloud discovery configuration and, later, explicitly shared SSH credentials within multi-user tenants
- production secret-manager integration for Stripe and other service credentials before public SaaS deployment
- richer billing operations such as invoice history, refunds/credits, taxes, coupons, metering, and billing-admin delegation
- additional outbound integrations such as Jira, Slack, ServiceNow, and SIEM export after the GitHub issue boundary is accepted
- richer remediation analytics and censored-aware timing metrics
- additional SBOM formats and complementary SBOM engines such as Syft where they add independent value
- deeper license/dependency governance
- private registry authentication beyond current GitHub/ECR paths
- expanded release signing/provenance controls
- cross-source vulnerability/inventory correlation
- automated but bounded reassessment scheduling after persistent assets exist
- additional cloud providers
- agent-based assessment only if a later threat/cost review justifies it
- hosted policy registry, policy key rotation/revocation, multi-signature policy, KMS/HSM signing, and tenant-scoped policy distribution after the Sprint 62 offline trust boundary is accepted
- invitation management UI and optional configured mail delivery after the Sprint 69 API/security boundary is accepted
- custom project roles, nested teams, and external identity group synchronization after the Sprint 71 ACL boundary is accepted
- legacy `ROADMAP.md` consolidation; this file remains authoritative for the active sprint sequence until the historical roadmap is normalized

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
