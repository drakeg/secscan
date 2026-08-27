# User authentication

Sprint 41 adds local browser accounts and server-side sessions as the identity foundation for future administration, organizations, feature entitlements, and subscription paywalls.

## First-run workflow

1. Copy `.env.example` to `.env`.
2. Keep `SECSCAN_REGISTRATION_ENABLED=true` for bootstrap.
3. Start secscan with `docker compose up --build --wait`.
4. Browse to the configured secscan URL. Unauthenticated browser requests are redirected to `/login`.
5. Choose **Create an account**. The first successfully registered account becomes the local `admin`.
6. After intended local accounts exist, set `SECSCAN_REGISTRATION_ENABLED=false` when open self-registration is not desired and restart the service.

## Password and session security

Passwords are salted and derived with Python's `hashlib.scrypt`; plaintext passwords are never stored. Session tokens are generated with the `secrets` module and only SHA-256 token digests are stored in SQLite. The browser receives the opaque token only as an `HttpOnly`, `SameSite=Strict` cookie.

Sessions expire after seven days. Logout removes the server-side session and clears the cookie. Set `SECSCAN_SESSION_COOKIE_SECURE=true` only when the service is actually delivered over HTTPS.

## API bearer-token compatibility

`SECSCAN_API_TOKEN` remains supported for non-browser automation. A valid bearer token can access the existing API without a browser session. Browser session middleware injects the configured compatibility bearer token only into the internal request boundary after a valid session has been established, so deployments that already enable API bearer protection can still use browser login.

## Administrator foundation

The first registered account receives role `admin`; subsequent self-registered accounts receive role `user`. Sprint 41 includes a server-enforced administrator endpoint at `GET /api/v1/admin/users`. Responses expose only public account metadata.

This is intentionally a foundation rather than a complete administration product. Account enable/disable controls, role assignment UI, invitations, audit events, organizations, tenant isolation, entitlements, and billing belong to later sprints.

## Registration policy

`SECSCAN_REGISTRATION_ENABLED=true` permits registration. Set it to `false` to disable both the registration page and registration API. Disabling registration does not disable existing accounts or sessions.

## Current limitations

- no password-reset email flow
- no email verification
- no MFA
- no OAuth/OIDC/SAML
- no organization or tenant ownership model yet
- no billing provider or paywall logic

These are deliberate boundaries so identity and authorization can stabilize before subscription features are attached to them.
