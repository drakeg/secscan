# Sprint 59 — Tenant and Authorization Isolation

## Goal

Introduce the first enforceable tenant boundary for the authenticated secscan service so one signed-in account cannot list, read, cancel, download artifacts from, or derive assets from another account's scan jobs.

## Scope

This sprint treats each registered account as its own initial tenant. The tenant identifier is persisted independently from the user's role so a later sprint can evolve the model toward multi-user tenant/project membership without changing job and asset ownership again.

The increment includes:

- a persisted `tenant_id` on authenticated users, with existing users deterministically backfilled to their own user ID
- a persisted `tenant_id` on service jobs
- tenant-scoped session submission, job listing, job detail, cancellation, artifact listing/download, and derived asset inventory
- tenant-aware asset identity so the same scanner/target may exist independently in different tenants
- migration of legacy local jobs to the original admin tenant when one can be identified safely; otherwise legacy jobs remain in a reserved system scope
- regression coverage proving that two authenticated users cannot observe or operate on one another's jobs or assets

## Authorization model

### Browser/session users

A valid session carries one tenant identity. Service job and asset APIs apply that tenant identity server-side. Client-supplied tenant identifiers are not accepted.

Cross-tenant object lookup fails as `404` so an authenticated user cannot use the API to confirm another tenant's job or asset identifiers.

### Legacy shared bearer token

The existing optional `SECSCAN_API_TOKEN` is retained as a **local system/operator compatibility path**. It is not represented as tenant-isolated authentication and may access system-wide service data. Future SaaS deployment must replace or constrain this compatibility path before being exposed outside the trusted local/operator boundary.

## Migration behavior

- `auth_users.tenant_id` is added if absent and backfilled to each user's existing ID.
- `service_jobs.tenant_id` is added if absent.
- When the shared database already contains an original admin account, pre-Sprint-59 jobs are assigned to that admin's tenant so the original local operator retains history after the migration.
- If no authenticated account can be identified, legacy jobs use a reserved system tenant rather than being assigned to an arbitrary future user.
- `service_assets` is derived state and is rebuilt into the tenant-aware schema from durable job history rather than guessing ownership from the old global asset table.

## Security boundaries

- No request body/query/header can select another tenant.
- Tenant filtering is enforced in storage queries, not only in browser JavaScript.
- Job artifacts inherit access from their owning job.
- Asset IDs include tenant identity, preventing cross-tenant identity collision for equal scanner/target pairs.
- The existing global `admin` role does not bypass tenant filtering for session requests.
- No organization invitations, tenant switching, shared projects, or cross-tenant administration are introduced in this increment.

## Out of scope

- multi-user tenant membership/invitations
- project-level sub-scoping inside a tenant
- tenant switching
- per-tenant API keys or OAuth/OIDC
- billing/subscription enforcement
- tenant-aware SSH credential sharing
- tenant-aware AWS discovery configuration
- production SaaS deployment

These remain follow-on work and must not be inferred as complete from this foundation.

## Cost

Current and projected recurring secscan infrastructure/service cost remains **$0**. The change uses the existing SQLite database and local filesystem.

## Acceptance criteria

- fresh databases create tenant-aware user, job, and asset schemas
- repeat migrations are safe
- existing users receive deterministic tenant IDs
- legacy jobs are migrated according to the documented original-admin/system rule
- a session user's submitted job is persisted with the server-derived tenant ID
- session job list/detail/cancel/artifact APIs cannot access another tenant's records
- derived asset list/detail APIs cannot access another tenant's assets
- the same scanner/target can exist as independent assets in two tenants
- the optional shared bearer-token path remains explicitly system-scoped and backward compatible for trusted local use
- Ruff, mypy, pytest, wheel/clean-install validation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before merge
