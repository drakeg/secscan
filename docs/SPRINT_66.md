# Sprint 66 — Tenant-Isolated SSH Host-Key Trust

## Goal

Close the remaining cross-tenant SSH trust gap after Sprint 65 tenant-scoped encrypted credential profiles.

## Scope

Tenant-scope SSH host-key discoveries and approved trust records at the SQLite boundary while preserving the explicit trusted system/operator execution context.

This sprint:

- adds `tenant_id` ownership to pending host-key discoveries
- adds `tenant_id` ownership to approved SSH host trust
- changes approved-host uniqueness from global `(host, port)` to `(tenant_id, host, port)`
- scopes discovery approval, lookup, listing, and deletion to the authenticated tenant context
- allows different tenants to approve different keys for the same host/port without overwriting each other
- prevents one tenant from approving another tenant's pending discovery
- keeps the explicit `SYSTEM_TENANT_ID` execution context available for trusted operator workflows
- migrates legacy global host trust to the original admin tenant when that tenant is identifiable, falling back to the system tenant when it is not
- keeps migration idempotent

The existing `SshCredentialTenantMiddleware` already binds authenticated requests to the session tenant, so the admin host-trust API inherits the new storage isolation without duplicating tenant selection logic in each endpoint.

## Security boundaries

- Tenant identity is derived from authenticated request context, not from request JSON, query strings, or URL parameters.
- Browser/API callers cannot choose another tenant ID.
- Pending discovery IDs cannot cross tenant boundaries.
- Approved key replacement is scoped to the same tenant, host, and port.
- The system context is intentionally privileged for trusted local/operator execution and is not exposed as a browser-selected tenant.
- Existing strict SSH host-key validation, fingerprint verification, bounded in-process discovery, and approval-before-trust semantics remain unchanged.

## Migration

Legacy `ssh_host_key_discoveries` and `ssh_trusted_host_keys` tables without `tenant_id` are migrated transactionally by SQLite connection scope into tenant-aware replacements. Existing rows are assigned to the earliest original administrator's tenant when available. Running migration repeatedly is a no-op after the tenant-aware schema exists.

## Cost

Current and projected recurring secscan service cost remains **$0**. This is a local SQLite authorization/storage change and introduces no paid infrastructure or external service.

## Acceptance criteria

- two tenants may independently trust the same host/port
- one tenant cannot list, retrieve, delete, or approve another tenant's trust/discovery records
- legacy global trust migrates to the original admin tenant and remains readable there
- migration is repeatable without duplicating or losing trust records
- existing host-key discovery/fingerprint behavior remains unchanged
- authenticated credential decryption receives only the current tenant's approved host-key additions
- Python 3.12/3.14 quality/package checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL result are green before merge
