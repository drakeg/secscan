# Sprint 68 — Multi-User Tenant Membership and Switching

## Goal

Extend the existing one-account/one-tenant foundation so an existing secscan account can be an explicit member of more than one tenant and can switch its active tenant without weakening the tenant isolation already enforced for jobs, assets, SSH credentials, and SSH host trust.

## Scope

This sprint will:

- add first-class tenant and tenant-membership records while preserving existing tenant IDs
- migrate every existing account into an owner membership for its current tenant
- add an active tenant to authenticated sessions
- resolve `request.state.secscan_user.tenant_id` from the session's active tenant only after membership validation
- allow a tenant owner to add an existing secscan account to that tenant by normalized email
- allow a tenant owner to remove a non-owner member from that tenant
- allow an authenticated account to list its memberships and switch only to a tenant where it has an active membership
- expose a small authenticated account UI/API for tenant membership and switching
- invalidate/fail closed if a session references a tenant membership that no longer exists
- add focused migration, authorization, tenant-switch, and isolation regression tests

## Security boundaries

- Tenant IDs are never accepted from anonymous callers.
- Switching tenants requires an existing membership for the authenticated account.
- Membership administration requires the caller to be an owner of the active tenant.
- Owners cannot remove themselves through the member-removal path; ownership transfer is deferred.
- Adding members is limited to already-registered secscan accounts in this sprint. No invitation tokens or email delivery are introduced yet.
- Existing global `admin`/`user` account roles remain unchanged and do not automatically grant membership in another tenant.
- Existing tenant-scoped storage must continue to derive tenant identity from authenticated request state, not request payloads.
- No cross-tenant asset, scan, SSH credential, SSH trust, billing, or secret sharing is introduced.

## Explicitly deferred

- invitation creation/acceptance and email delivery
- ownership transfer and multiple-owner policy beyond the migrated original owner
- tenant creation/deletion/renaming UI
- project-level roles or authorization
- tenant-scoped API keys
- OIDC/SAML/external identity
- shared cloud-discovery configuration
- explicit cross-tenant or tenant-shared SSH credentials

## Cost

Current and projected recurring secscan service cost remains **$0**. This sprint uses only the existing SQLite/session application boundary.

## Acceptance criteria

- legacy accounts retain access to the same tenant data after migration
- each legacy account receives an owner membership for its existing tenant
- a tenant owner can add an existing account as a member
- non-owners cannot modify membership
- a user can switch only among tenants where membership exists
- `User.tenant_id` reflects the active session tenant after switching
- removing a member prevents new switches to that tenant and invalidates an already-active membership on the next authenticated request
- existing tenant-isolation tests remain green
- Python 3.12/3.14 quality/tests, wheel/package validation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and separate GitHub Advanced Security CodeQL are green before merge
