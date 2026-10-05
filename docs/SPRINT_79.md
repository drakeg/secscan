# Sprint 79 — Authentication Precedence Hardening

## Goal

Ensure an explicitly supplied secscan tenant API key is authoritative and fails closed when invalid instead of silently falling back to a valid browser session in downstream tenant-aware middleware.

## Security and correctness boundaries

- A bearer credential with the `secscan_` prefix is treated as an explicit tenant API-key authentication attempt.
- An invalid, revoked, expired, disabled-principal, or otherwise unauthenticated tenant API key returns HTTP 401.
- A valid session cookie cannot rescue an invalid explicit tenant API-key attempt.
- Valid tenant API keys retain their existing tenant isolation and non-admin credential semantics.
- Requests without a secscan tenant bearer key retain existing session behavior.
- Existing service-level bearer-token behavior is unchanged.
- No hosted service, paid dependency, or recurring infrastructure cost is introduced.

## Increment 1 — SSH credential middleware fail-closed precedence

Align SSH credential tenant resolution with the tenant API-key authentication middleware by rejecting an invalid explicit `secscan_` bearer credential before session fallback.

## Acceptance

- invalid explicit tenant API keys return 401 even when a valid session cookie is present
- valid tenant API keys continue to select their principal tenant
- cross-tenant SSH credential isolation remains enforced
- session-only SSH credential flows remain unchanged
- Python/package/container/Compose/CI/CodeQL gates remain green
- recurring infrastructure cost remains $0
