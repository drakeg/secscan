# Sprint 74 — External Identity / OpenID Connect Foundation

## Goal

Add a provider-neutral OpenID Connect (OIDC) authentication foundation before any production SaaS exposure, without weakening existing tenant, project, session, invitation, or API-key boundaries.

## Scope

- Add optional OIDC provider configuration using standard issuer discovery.
- Add browser login initiation and callback handling.
- Validate OIDC state, nonce, issuer, audience, signature, expiry, and required claims.
- Map a verified external identity to exactly one local secscan user record.
- Preserve the existing secscan session cookie and active-tenant model after successful OIDC authentication.
- Keep password login available unless an operator explicitly disables it in a later sprint.
- Add focused tests for authentication success, invalid/missing claims, replay-resistant state/nonce handling, disabled local users, and tenant isolation.
- Preserve the $0 recurring-service baseline; no external IdP account or paid service is activated by this sprint.

## Security boundaries

- OIDC is authentication only. It does not grant tenant membership, tenant ownership, project access, global administration, or API-key privileges.
- A verified external subject must be linked to an existing local user before it can authenticate.
- Email alone is not a durable external identity key.
- External identity linkage is unique by issuer plus subject.
- A disabled local user cannot authenticate through OIDC.
- A valid OIDC login creates the same bounded local session model used by password login.
- OIDC callback parameters and tokens are never logged as secrets.
- State and nonce values are single-use and expire quickly.
- Discovery/JWKS retrieval must use HTTPS except for explicit local-development fixtures used only in tests.
- Provider misconfiguration fails closed.

## Compatibility

- Existing password authentication, invitations, tenant switching, project ACLs, tenant API keys, and historical sessions remain supported.
- Existing users are not automatically linked to external identities.
- No tenant or role is inferred from IdP groups, domains, or email claims during Sprint 74.
- No production IdP is required to run the default local/container development flow.

## Acceptance criteria

- Operator can configure one OIDC issuer, client ID, and client secret through environment/server configuration.
- Login initiation generates bounded state and nonce values and redirects only to the configured issuer authorization endpoint.
- Callback validates the authorization response and ID token before creating a local session.
- A linked, enabled local user can authenticate and receives the same active-tenant session semantics as password login.
- Unknown external subjects fail closed and do not auto-create users or tenants.
- Disabled local users fail closed.
- Replayed, expired, mismatched-state, mismatched-nonce, wrong-issuer, wrong-audience, unsigned/invalid-signature, or expired tokens are rejected.
- OIDC authentication does not bypass tenant membership or project ACLs.
- Existing password login remains compatible.
- Python 3.12/3.14 checks, package build, Docker/Compose smoke tests, Trivy, and CodeQL remain green.
- No paid service or recurring spend is introduced.

## Deferred

- Just-in-time user provisioning.
- Domain-based enrollment.
- IdP group-to-tenant or group-to-project synchronization.
- Multiple simultaneous OIDC providers.
- SAML.
- SCIM.
- Mandatory SSO / password-login disablement.
- Organization-managed IdP policy enforcement.
- Automatic external identity linking by email.

## Identity foundation implementation

The first Sprint 74 increment adds strict optional OIDC provider configuration and durable external-identity linkage without enabling live redirects or token exchange yet. Configuration requires issuer, client ID, and client secret together; issuer URLs are HTTPS-only outside explicit localhost test fixtures, and public configuration metadata never includes the client secret. External identities are keyed only by the exact validated issuer identifier plus exact subject and link to an existing local user. Email, domain, tenant, role, and project claims are not persisted or inferred. Linkage collisions fail closed, and one local user may have at most one subject per issuer unless the old link is explicitly removed first.

## Login transaction state

OIDC browser login state now has a dedicated persistence boundary before any live provider callback is enabled. Each login attempt receives cryptographically random state and nonce values, while only SHA-256 digests are persisted. Transactions expire after 10 minutes, state is single-use, expired state is burned even when rejected, and nonce verification uses constant-time digest comparison. Malformed state/nonce input fails closed. This increment does not yet perform discovery, redirects, token exchange, or ID-token validation.

## Discovery and authorization request validation

Sprint 74 now validates provider discovery metadata before constructing any browser authorization request. The discovery issuer must exactly match the configured issuer, authorization/token/JWKS endpoints must use HTTPS outside explicit localhost fixtures, authorization-code flow must be advertised, and at least one signed ID-token algorithm must remain after excluding `none`. Authorization URLs are then built only from this validated metadata with the configured client ID, an HTTPS redirect URI, `response_type=code`, `scope=openid`, and the one-time state/nonce pair. Client secrets are never included in the browser URL. Network retrieval, token exchange, and callback authentication remain separate follow-up boundaries.

## Bounded discovery retrieval

Provider discovery can now be retrieved using the OIDC well-known URL derived from the configured issuer. Retrieval uses a five-second timeout, a 256 KiB hard response limit, JSON content-type enforcement, UTF-8 JSON object validation, and an HTTP client path that does not follow redirects. The resulting document still passes through the exact issuer and endpoint validator before it can be used. This keeps network retrieval from expanding the trust boundary to a redirect target or oversized/non-JSON response. Token exchange, JWKS retrieval, ID-token verification, and session creation remain separate follow-up increments.

## JWKS and ID-token verification

Sprint 74 now has a bounded cryptographic verification boundary for OIDC ID tokens before any local session is created. JWKS retrieval reuses the redirect-disabled HTTPS fetch path with a five-second timeout, a 256 KiB hard limit, JSON media-type enforcement, and a required non-empty `keys` set. ID tokens are currently limited to RSA PKCS#1 signatures (`RS256`, `RS384`, and `RS512`) using the existing `cryptography` dependency. Verification requires an advertised algorithm, an exact matching `kid`, a signing-use RSA key of at least 2048 bits, a valid signature, exact configured/discovered issuer, the configured client ID in `aud`, correct `azp` when multiple audiences are present, an unexpired `exp`, a valid subject, and the one-time transaction nonce. Signature or claim failure does not create a local session. Token exchange and local session creation remain separate follow-up increments.

## Authorization-code token exchange

Sprint 74 now has a bounded authorization-code exchange boundary. The callback code is accepted only as a compact opaque value and is POSTed as `application/x-www-form-urlencoded` to the already validated token endpoint with `grant_type=authorization_code` and the exact HTTPS redirect URI. Client credentials use HTTP Basic authentication and are not placed in the form body. The default exchange path disables redirects, uses a five-second timeout and 256 KiB response limit, requires JSON, and requires a non-empty bounded `id_token`. The returned ID token is not trusted by this layer; it must still pass the separate JWKS/signature/claim verifier before identity resolution or session creation.
