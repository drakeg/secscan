# Sprint 41 — User Accounts and Authentication Foundation

## Goal

Establish a secure local identity and session foundation for the GUI so secscan can grow toward administrator controls, organizations, feature entitlements, and later subscription paywalls without coupling application behavior directly to a billing provider.

## Stories

1. A new operator can register a local account through the browser when registration is enabled.
2. The first registered account becomes the bootstrap administrator.
3. Registered users can log in and log out using server-side sessions.
4. The browser can determine the current authenticated user without receiving password hashes or session secrets.
5. Administrator-only endpoints have an explicit role boundary that later admin screens can build on.
6. Existing API bearer-token automation remains supported and independent from browser sessions.

## Acceptance criteria

- email addresses are normalized and unique
- passwords are never stored in plaintext and use a salted memory-hard password derivation function
- session tokens are cryptographically random; only token digests are stored in SQLite
- session cookies are HttpOnly and SameSite=Strict; Secure can be enabled for TLS deployments
- sessions have a bounded lifetime and logout invalidates the server-side session
- the first successfully registered user is assigned the `admin` role; later self-registered users receive `user`
- registration can be disabled with configuration after bootstrap
- `/api/v1/auth/me` returns only public account metadata
- administrator authorization is enforced server-side rather than only by browser controls
- authentication data uses the existing persistent service SQLite boundary; no external identity provider or paid service is required
- current and projected recurring infrastructure/service cost remains $0

## Security boundaries

- no OAuth/OIDC/SAML in this sprint
- no password reset email workflow in this sprint
- no MFA in this sprint
- no organizations, tenant isolation, feature entitlements, billing provider, or paywall logic in this sprint
- no storage of passwords, plaintext session tokens, or authentication secrets in logs/reports/job records
- the existing shared API bearer token remains an automation compatibility mechanism, not a substitute for user identity

## Validation

- unit tests for password hashing/verification, duplicate registration, bootstrap admin assignment, session creation/expiry/revocation, and disabled registration
- API/browser tests for register, login, logout, current-user metadata, unauthorized access, and admin authorization
- full `bash scripts/preflight.sh`
- Docker/Compose service startup and health validation
- CodeQL and existing container vulnerability gate

## Cost outlook

SQLite-backed local accounts and sessions add no recurring service cost. Hosted identity, transactional email, MFA delivery, organizations, entitlements, and billing remain future decisions and require separate cost/security review.
