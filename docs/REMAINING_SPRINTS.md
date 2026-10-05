# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 76

Sprints 0–75 are complete, including the capabilities previously summarized here plus tenant-isolated SSH credentials and SSH host-key trust, bounded ECS/EKS workload association, an opt-in tenant-bound Stripe subscription lifecycle, bounded GitHub Issues export, offline Ed25519-signed policy/governance bundles, authenticated network-range and Windows host workflows, multi-user tenant membership with session-scoped tenant switching, owner-controlled expiring tenant invitations with authenticated single-use acceptance, tenant-owned projects with validated optional scan-job association and project-specific viewer/operator access control, tenant-scoped API keys, tenant-owned reusable SSH credentials with owner administration, safe legacy migration, disabled-state enforcement, API-key use, and project ACL enforcement, and an optional provider-neutral OIDC login flow with bounded discovery/JWKS/token exchange, replay-safe state/nonce validation, cryptographic ID-token verification, explicit issuer/subject linking, and reuse of the existing local session and tenant model.

## Sprint 76 closeout

Sprint 76 — Security Boundary Hardening is complete. It delivered upgrade-safe reassessment persistence, strict claim-token completion, remote-only scheduled repository targets, execution-time authorization re-evaluation, safe project association before enqueue, validation-before-persistence, scheduler exception resilience, explicit legacy duplicate migration handling without silent data loss, and lifecycle API authorization regression coverage.

See `docs/SPRINT_76.md` for the completed acceptance record.

## Sprint 77 closeout

Sprint 77 — OIDC Protocol Hardening is complete. It delivered standards-compliant Basic client authentication, PKCE S256, provider-error state consumption, strict compact JWT/JWK validation, and bounded temporal-claim validation while preserving explicit identity linking and the existing local-session/tenant authorization model.

See `docs/SPRINT_77.md` for the completed acceptance record.

## Sprint 78 closeout

Sprint 78 — Reassessment Scheduler Correctness is complete. It made scheduler claim outcomes explicit so failed claimed work cannot postpone later due schedules, and it made project-scoped job creation atomic so a committed job can no longer be observed without its project association.

See `docs/SPRINT_78.md` for the completed acceptance record.

## Current sprint

### Sprint 79 — Authentication Precedence Hardening

Make explicit tenant API-key authentication fail closed consistently so an invalid bearer credential cannot silently fall back to a valid browser session in tenant-aware middleware.

See `docs/SPRINT_79.md` for scope and acceptance criteria.

## Candidate remaining sprints

Later sprint numbers remain unassigned until planning confirms exact scope, acceptance criteria, security boundaries, dependencies, and cost.

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
