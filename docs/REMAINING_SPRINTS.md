# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 69

Sprints 0–69 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, multi-user tenant membership with session-scoped tenant switching, and owner-controlled expiring tenant invitations with authenticated single-use acceptance.

## Current sprint

### Sprint 70 — Tenant-Owned Projects and Project Authorization

Add a small project boundary within tenants. Projects are owned by exactly one tenant; tenant members may list and use enabled projects while owners administer them. Scan jobs may optionally reference a project only after tenant-scoped validation. Existing unprojected jobs remain valid, and project-specific ACLs are deferred.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 70 is accepted, reprioritize the remaining backlog before assigning Sprint 71.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- project-specific member roles/ACLs after the tenant-owned project boundary is accepted
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
- legacy `ROADMAP.md` consolidation; this file remains authoritative for the active sprint sequence until the historical roadmap is normalized

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
