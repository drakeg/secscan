# Sprint 65 — Tenant-Isolated SSH Credential Profiles

## Goal

Close the cross-tenant secret-use gap left after Sprint 59 by making encrypted SSH credential profiles, defaults, and remembered host bindings tenant-scoped at the SQLite storage boundary.

## Security problem

Service jobs and derived assets are tenant-isolated, but the existing `ssh_credential_profiles` and `ssh_host_credentials` tables are global. Authenticated users therefore share one profile namespace, one default profile, one host-binding namespace, and profile-ID lookup. Because Linux and Windows host submissions accept a credential profile ID, this can allow one tenant to enumerate metadata for or select another tenant's encrypted SSH credential profile.

## Scope

- add a request-scoped credential tenant context derived from the authenticated session
- make profile names unique per tenant rather than globally
- allow one default profile per tenant
- make remembered host-to-profile bindings tenant-scoped
- require tenant equality for profile list/get/default/delete and authenticated decryption
- preserve the trusted system/operator compatibility path for non-session execution
- migrate legacy global credential profiles and host bindings deterministically
- preserve existing Fernet encryption, key validation, temporary-file handling, strict SSH host-key verification, and key-only authentication

## Migration

When the existing credential tables do not yet contain `tenant_id`, secscan rebuilds them transactionally into the tenant-aware schema. Existing profiles and remembered host bindings are assigned to the oldest original admin tenant when one is identifiable from `auth_users`; otherwise they are assigned to the reserved `__system__` scope.

The migration is idempotent. The new schema uses:

- `UNIQUE (tenant_id, name)` for profile names
- one partial unique default index per tenant
- `PRIMARY KEY (tenant_id, host)` for remembered host bindings
- a composite foreign key tying each host binding to a profile in the same tenant

## Worker boundary

Authenticated request-time profile selection is tenant-checked before a Linux or Windows job is persisted. Profile-backed scans execute in worker threads, where request `ContextVar` state is not relied upon. The worker may decrypt the already-validated profile ID through the reserved system execution context; users cannot reach that path without first passing the tenant-scoped request lookup.

This preserves the existing background execution model without copying secret material into job records or thread arguments.

## Deliberately deferred

- SSH host-key trust records remain system-wide in this sprint. They contain public host keys rather than authentication private keys, and existing credential decryption continues to merge approved global trust records into ephemeral `known_hosts` files. Tenant-scoped host-trust ownership/approval is backlogged separately.
- multi-user tenant membership, invitations, tenant switching, and shared credential ownership are not added
- tenant-aware cloud discovery configuration is not added
- per-tenant API keys/OIDC are not added
- no credential export or secret-return API is added

## Cost

Current/projected recurring secscan infrastructure and service cost remains **$0**. The change uses the existing SQLite and `cryptography` dependencies.

## Acceptance criteria

- two tenants may create profiles with the same display name independently
- each tenant has an independent default profile and remembered host binding namespace
- one tenant cannot list, get, make default, delete, bind, resolve, or authenticate with another tenant's profile
- encrypted secret material remains absent from API responses and job records
- legacy global profiles/bindings migrate to the original admin tenant or reserved system scope and repeat migration safely
- existing Linux and Windows profile-backed workflows continue to use temporary owner-readable key/trust files and delete them after execution
- package integrity explicitly includes the credential-tenancy module
- Ruff, mypy, pytest, wheel/clean-install validation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before acceptance
