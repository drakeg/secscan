# Sprint 77 — OIDC Protocol Hardening

## Goal

Harden the existing provider-neutral OIDC authorization-code flow against protocol edge cases before adding identity-management surface.

## Security boundaries

- Existing explicit issuer/subject links remain required; no automatic account creation or linking.
- Existing local sessions and tenant authorization remain authoritative after login.
- OIDC network requests remain bounded, redirect-resistant, and HTTPS-only outside explicitly enabled localhost development.
- Secrets, authorization codes, PKCE verifiers, state, nonce, and ID tokens must not be persisted in public metadata or logs.
- No hosted identity dependency or recurring infrastructure cost is introduced.

## Planned increments

1. Correct `client_secret_basic` credential encoding for reserved, Unicode, and delimiter characters.
2. Add PKCE S256 with transaction-bound verifier handling.
3. Consume callback state on provider error responses so error callbacks cannot leave reusable login transactions.
4. Tighten JWT protected-header/base64url and JWK signing-key constraints.
5. Add bounded temporal-claim validation for `exp`, `iat`, and `nbf` with explicit clock-skew semantics.
6. Run acceptance/security review and update authentication documentation.

## Acceptance

- standards-compliant Basic credentials work for client IDs/secrets containing reserved or Unicode characters
- authorization requests carry an S256 challenge and token exchange carries only the matching verifier
- provider error callbacks validate and consume state before returning failure
- malformed/non-canonical compact JWT segments and unsupported critical headers fail closed
- JWKs incompatible with signature verification fail closed
- invalid, non-finite, overflowing, future-issued, expired, or not-yet-valid temporal claims fail closed
- existing OIDC browser flow, explicit linking, manual login, API keys, and tenant sessions remain compatible
- Python/package/container/Compose/CI/CodeQL gates remain green
- recurring infrastructure cost remains $0


## Increment 2 — PKCE S256

OIDC authorization-code logins now bind each transaction to a high-entropy PKCE verifier. Authorization requests send only the derived S256 challenge; the server-side transaction store retains the verifier until the single-use state is consumed, and token exchange sends it only to the validated provider token endpoint. Existing transaction databases migrate in place; pre-PKCE outstanding transactions fail closed and require a fresh login.


## Increment 3 — Provider error state consumption

OIDC callback errors now require a matching state when one was issued and consume that transaction before returning the provider failure. This preserves the same single-use CSRF/replay boundary for denied or failed provider callbacks as for successful authorization-code callbacks. Unknown/replayed state fails closed and no provider error text is reflected to the client.
