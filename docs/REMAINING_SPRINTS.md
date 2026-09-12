# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 67

Sprints 0–67 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, and the existing account-to-tenant isolation foundation.

## Current sprint

### Sprint 68 — Multi-User Tenant Membership and Switching

Add first-class tenant memberships and session-scoped active-tenant switching for already-registered accounts. Preserve existing tenant IDs and isolation, migrate each legacy account as owner of its current tenant, require owner authorization for membership changes, and fail closed when a session no longer has membership in its selected tenant.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 68 is accepted, reprioritize the remaining backlog before assigning Sprint 69.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- invitation creation/acceptance and email delivery for multi-user tenants
- project-level authorization and tenant-owned projects
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
- legacy `ROADMAP.md` consolidation; this file remains authoritative for the active sprint sequence until the historical roadmap is normalized

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
