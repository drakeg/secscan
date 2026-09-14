# Sprint 72 — Tenant-Scoped API Keys

## Goal

Replace the service-wide API-token assumption with a durable tenant-scoped API-key boundary suitable for automation while preserving existing session authentication and fail-closed tenant/project authorization.

## Scope

- tenant-owned API-key records with stable IDs, display names, creation metadata, enabled/revoked state, and optional expiration
- cryptographically random bearer secrets shown only at creation; persist only a one-way digest
- tenant owners may create, list metadata for, and revoke keys in the active tenant
- authenticated API-key requests resolve to exactly one tenant identity
- API-key actors may submit and inspect tenant-scoped scan jobs subject to existing project ACL rules
- cross-tenant project/job/resource access remains non-disclosing and fail closed
- revocation and expiration take effect without restarting the service
- preserve session/cookie authentication and existing unprojected job compatibility
- focused persistence, authentication, revocation, expiration, tenant-isolation, and project-authorization tests
- update active sprint documentation and keep the $0 recurring-service baseline

## Authorization boundary

- a key belongs to exactly one tenant and never grants access outside that tenant
- only an active tenant owner can administer tenant keys
- key possession does not imply tenant ownership and does not bypass project ACLs
- global secscan administration does not bypass tenant/project ownership
- disabled/revoked/expired keys authenticate as invalid
- API responses never return stored secret material or secret digests

## Compatibility

Existing browser/session authentication remains supported. The legacy service-wide `SECSCAN_API_TOKEN` path remains compatibility-only during this sprint and must not gain tenant/project privileges; deprecation/removal requires a later explicit migration decision.

## Deferred

- OIDC/SAML/external identity federation
- per-key fine-grained scopes beyond tenant/project authorization
- key rotation grace windows
- service accounts distinct from API keys
- quotas/rate limits/billing by key
- production secret-manager integration
- external identity group synchronization

## Acceptance criteria

- owner can create a tenant API key and receives the secret exactly once
- only a digest is persisted
- owner can list key metadata without recovering the secret and can revoke a key
- valid key authenticates into its tenant and cannot cross tenant boundaries
- revoked/expired/invalid keys fail closed immediately
- project-restricted scan submission and evidence access honor Sprint 71 viewer/operator rules for the API-key actor model selected by implementation
- browser/session authentication and legacy unprojected jobs remain compatible
- Python 3.12/3.14 quality/tests, package integrity, Docker/Compose smoke, Trivy, and CodeQL are green
- no paid service or recurring spend is introduced
