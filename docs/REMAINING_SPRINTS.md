# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 73

Sprints 0–73 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, multi-user tenant membership with session-scoped tenant switching, owner-controlled expiring tenant invitations with authenticated single-use acceptance, tenant-owned projects with validated optional scan-job association and project-specific viewer/operator access control, tenant-scoped API keys, and tenant-owned reusable SSH credentials with owner administration, safe legacy migration, disabled-state enforcement, API-key use, and project ACL enforcement.

## Current sprint

### Sprint 74 — External Identity / OpenID Connect Foundation

Add an optional provider-neutral OIDC authentication path before production SaaS exposure. External identity verifies authentication only; existing local tenant membership, project ACLs, session semantics, invitations, and API-key boundaries remain authoritative. Unknown external identities do not auto-create users or tenants, and the sprint introduces no paid identity service.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 74 is accepted, reprioritize the remaining backlog before assigning Sprint 75.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

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
- per-key fine-grained scopes, service accounts, and key rotation grace windows after the Sprint 72 tenant-key boundary is accepted
- legacy `ROADMAP.md` consolidation; this file remains authoritative for the active sprint sequence until the historical roadmap is normalized

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
