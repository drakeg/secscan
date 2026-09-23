# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 74

Sprints 0–74 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, multi-user tenant membership with session-scoped tenant switching, owner-controlled expiring tenant invitations with authenticated single-use acceptance, tenant-owned projects with validated optional scan-job association and project-specific viewer/operator access control, tenant-scoped API keys, tenant-owned reusable SSH credentials with owner administration, safe legacy migration, disabled-state enforcement, API-key use, and project ACL enforcement, and an optional provider-neutral OIDC login flow with bounded discovery/JWKS/token exchange, replay-safe state/nonce validation, cryptographic ID-token verification, explicit issuer/subject linking, and reuse of the existing local session and tenant model.

## Current sprint

### Sprint 75 — Reassessment Scheduling Foundation

Add local, bounded reassessment scheduling for persistent assets without introducing a hosted scheduler, paid queue, or autonomous unbounded scanning. Scheduling remains tenant/project scoped, reuses the existing job and authorization boundaries, and requires an explicitly supported persistent asset/scan profile rather than arbitrary commands or targets.

Initial planning priorities:
- persist an opt-in reassessment schedule owned by exactly one tenant and, when applicable, one project
- support bounded daily/weekly cadence rather than arbitrary cron expressions
- require an existing supported asset and validated scan configuration
- expose next-run/last-run/status metadata without leaking credentials
- enqueue through the existing job path so tenant/project ACLs and scanner validation still apply
- prevent overlapping duplicate runs for one schedule
- allow owner/operator pause/resume while preserving audit metadata
- keep local/container operation at $0 with no external scheduler or recurring service

Before implementation, define the exact supported asset types, authorization matrix, misfire/restart behavior, concurrency rules, and deterministic local test clock.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 75 is accepted, reprioritize the remaining backlog before assigning Sprint 76.

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
