# Sprint 80 — Session Lifecycle Security Review

## Goal

Verify that session authentication remains fail-closed when an account or tenant membership is changed, revoked, or expires. Prioritize narrowly scoped regressions over new authentication features.

## Committed increment — lifecycle audit and regression tests

- Audit existing session creation, lookup, tenant switching, and logout paths against the persistence schema and service middleware.
- Add or strengthen deterministic tests for expired and revoked session tokens, disabled accounts, and removed active-tenant membership where coverage is missing.
- Confirm that a tenant switch cannot persist after a failed authorization check.
- Fix only confirmed defects uncovered by that audit, with a failing regression test first.
- Keep the current authorization model, API response contracts, and supported Python versions unchanged.

## Explicitly excluded

- OAuth/OIDC provider changes or new identity providers.
- Password-reset workflows, user-facing account management redesign, and new multi-tenant privileges.
- New hosted services, billing dependencies, or recurring infrastructure spending.

## Security and persistence boundaries

- A revoked, expired, or otherwise invalid session must never authorize a request.
- Disabled accounts and removed active-tenant memberships must not continue to authorize a previously issued token.
- Session tokens must remain stored as digests and must not appear in logs or API responses.
- Tenant switching must enforce current membership and leave the previous tenant selection intact on failure.
- No schema migration is planned; any migration proposed after a confirmed defect requires separate review for restart safety and compatibility.

## Validation and acceptance

- New or existing regression tests prove each lifecycle invariant against SQLite-backed storage and relevant API middleware.
- Relevant Ruff, mypy, pytest, package-integrity, supported-Python, container, and CodeQL CI checks pass.
- Documentation is updated alongside any observable behavior change.
- No recurring infrastructure cost is introduced (projected additional cost: $0).

## Implementation order

1. Inventory current session and middleware behavior and tests.
2. Add missing failing or characterization regressions.
3. Make the smallest verified fix, if required.
4. Review full CI and close the sprint only after acceptance.

## Status

In progress. Initial SQLite-backed regression tests cover revoked and expired tokens, disabled users, revoked active-tenant membership, and failed tenant switches. Full CI acceptance and any additional middleware coverage remain outstanding. The completion of Sprint 79 is recorded in `docs/SPRINT_79.md`.
