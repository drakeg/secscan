# Sprint 73 — Tenant-Scoped Shared SSH Credentials

## Goal

Make reusable SSH credential records tenant-owned so authenticated host scanning can safely use shared credentials without allowing cross-tenant discovery or use.

## Scope

- Add tenant ownership to reusable SSH credential records.
- Require active tenant ownership for credential administration.
- Allow active tenant members to reference enabled credentials for permitted scans without exposing stored secret material.
- Preserve the existing encrypted/secret-handling behavior and tenant-isolated SSH host trust boundary.
- Add a safe migration path for existing credential records without silently assigning them across tenants.
- Add focused persistence, authorization, migration, scan-submission, and isolation tests.
- Preserve the $0 recurring-service baseline.

## Authorization rules

- Every reusable SSH credential belongs to exactly one tenant.
- Only an active owner of that tenant may create, update, disable, or remove the credential record.
- Active tenant members may use an enabled credential for an otherwise-authorized host scan but cannot retrieve the private key, password, passphrase, or equivalent secret material.
- Global secscan administrator status does not bypass tenant ownership.
- Client-supplied credential IDs are always resolved inside the active tenant boundary.
- Cross-tenant credential IDs fail closed and use non-disclosing errors.
- Project authorization remains an additional boundary when a scan is associated with a project.

## Compatibility and migration

- Existing direct/per-scan SSH credential flows remain supported during Sprint 73.
- Historical scan evidence remains readable.
- Existing reusable credential rows must not be silently assigned to an arbitrary tenant.
- Migration must require an explicit safe ownership decision for legacy rows or leave them unusable by tenant-scoped flows until ownership is established.

## Acceptance criteria

- Tenant owner can create, list metadata for, update, disable, and remove a tenant credential.
- Secret material is never returned by list/detail APIs after creation or update.
- A same-tenant member can reference an enabled credential for an authorized scan without gaining credential-administration rights.
- A different tenant cannot discover or use the credential, including by guessing its ID.
- Disabled credentials cannot be used for new scans.
- Legacy/unowned records do not become available to any tenant automatically.
- Existing direct credential submission and historical job/evidence behavior remain compatible.
- Python 3.12/3.14 checks, package build, Docker/Compose smoke tests, Trivy, and CodeQL remain green.
- No paid service or recurring spend is introduced.

## Deferred

- External secret-manager integrations.
- Automatic credential rotation and grace periods.
- Cloud-native SSH/session brokering.
- Per-project credential ACLs.
- User-specific private credential vaults.
- Agent-based host access.

## Legacy migration implementation

Legacy pre-tenant SSH credential rows are preserved encrypted but migrated with no tenant owner. Their former default flag is cleared, legacy host bindings are discarded, and tenant-scoped list/get/decrypt/resolve paths cannot use them. This intentionally requires a future explicit ownership/import action rather than inferring ownership from the first administrator or system tenant.

## Tenant API-key credential use

Tenant API keys may use enabled shared SSH credentials inside the bound tenant for scan submission, but they do not gain SSH credential-administration rights. A valid bearer key is authoritative over any simultaneously supplied session cookie for credential tenant selection, preventing mixed-auth tenant confusion.

## Credential updates

Tenant owners may update shared SSH credential metadata and rotate the stored private key and known_hosts material. Update responses contain metadata only; secret values and ciphertext are never returned. Partial metadata-only updates preserve the existing encrypted secret material.

## Disabled credential hardening

Disabled shared SSH credentials are now rejected inside the core credential store as well as at HTTP scan submission. Decryption, default assignment, and host binding all fail closed for disabled profiles, and implicit resolution ignores stale bindings or defaults that reference a disabled profile. This prevents internal or future call paths from bypassing lifecycle enforcement.
