# Remaining Sprint Sequence

This document turns the directional backlog into an ordered candidate sprint sequence. Only the current sprint is committed. Later sprint numbers remain candidates until sprint planning confirms exact stories, acceptance criteria, dependencies, security boundaries, and cost.

## Completed through Sprint 63

Sprints 0–63 are complete, including the capabilities previously summarized here plus an opt-in tenant-bound Stripe subscription lifecycle, a bounded GitHub Issues export that remains offline by default and requires explicit submission with an environment-only token, offline Ed25519-signed policy/governance bundles with fail-closed verification, and authenticated Web/API submission for the bounded 16-host sequential `network-range` scanner with oversized-CIDR expansion hardened before materialization.

## Current sprint

### Sprint 64 — Authenticated Windows Host Web/API Submission

Expose the existing strict key-only `windows-host` assessment through a dedicated authenticated service endpoint and browser workflow. Reuse encrypted SSH credential profiles for key/trust material, allow a validated per-scan Windows username override for `DOMAIN\\user` cases, retain strict host-key verification and fixed read-only PowerShell checks, require explicit authorization before persistence, and keep authenticated host workflows Professional-entitled.

## Candidate remaining sprints

No later sprint number is committed yet. After Sprint 64 is accepted, the backlog should be reprioritized before assigning Sprint 65.

## Backlog after the numbered candidate sequence

These remain valid ideas but are intentionally not assigned fixed sprint numbers yet:

- multi-user tenant membership, invitations, tenant switching, and project-level authorization after the Sprint 59 account-tenant foundation
- per-tenant API keys or external identity/OIDC before any production SaaS exposure
- tenant-aware sharing/ownership for SSH credentials and cloud discovery configuration
- production secret-manager integration for Stripe and other service credentials before public SaaS deployment
- richer billing operations such as invoice history, refunds/credits, taxes, coupons, metering, and billing-admin delegation
- additional outbound integrations such as Jira, Slack, ServiceNow, and SIEM export after the GitHub issue boundary is accepted
- EKS/Kubernetes workload association with explicit cluster/namespace/workload allow-lists and least-privilege RBAC
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

## Planning rule

A candidate sprint becomes committed only after the preceding sprint is accepted and planning verifies that the scope remains the highest-priority small demonstrable increment. Security/correctness issues discovered in production or CI supersede this ordering and are fixed immediately.
