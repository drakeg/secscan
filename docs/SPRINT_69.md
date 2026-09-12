# Sprint 69 — Tenant Invitations and Acceptance

## Goal

Extend Sprint 68 multi-user tenant membership with bounded, owner-controlled invitations so a tenant owner can invite an email address without granting access until the intended recipient authenticates and explicitly accepts the invitation.

## Scope

This sprint will:

- add tenant invitation records with tenant, normalized email, role, creator, creation time, expiry, acceptance time, and revocation time
- generate cryptographically random invitation tokens and persist only token digests
- allow only an owner of the active tenant to create, list, and revoke invitations
- default invitations to the `member` tenant role; ownership invitation/transfer remains deferred
- bind acceptance to an authenticated account whose normalized email exactly matches the invitation email
- create membership only after successful acceptance
- make acceptance single-use and fail closed for expired, revoked, already-used, malformed, or mismatched invitations
- revoke outstanding invitations when an owner directly adds the same registered account to the tenant
- expose focused authenticated API support for invitation creation, listing, revocation, and acceptance
- add migration, authorization, expiry, replay, email-binding, direct-membership invalidation, and tenant-isolation regression tests

## Security boundaries

- Raw invitation tokens are returned only at creation time and are never stored in SQLite or logs.
- Invitation lookup uses a SHA-256 token digest; raw token material is not persisted or compared against stored plaintext.
- Invitation tokens are high-entropy, URL-safe values generated with Python `secrets`.
- Only an owner of the invitation tenant can create, list, or revoke its invitations.
- The accepting account must be authenticated and its normalized email must exactly match the invitation target.
- Acceptance never accepts a tenant ID, role, or target email from the client as authority; those values come from the stored invitation.
- Invitations expire after a bounded lifetime and are single-use.
- Invitation acceptance cannot create an owner membership.
- Direct membership creation invalidates matching outstanding invitations for the same tenant/email.
- Global secscan `admin` status does not bypass tenant invitation or membership authorization.
- No invitation token, SMTP credential, password, session token, SSH credential, or other secret may appear in logs or persisted job evidence.

## Explicitly deferred

- invitation management UI
- invitation email delivery and SMTP integration
- ownership transfer and owner invitations
- multiple-owner governance
- tenant creation/deletion/renaming
- project-level authorization
- tenant-scoped API keys
- OIDC/SAML/external identity
- bulk invitations
- domain-wide invitations
- SCIM/provisioning
- third-party paid email service activation

## Cost

Current and projected recurring secscan service cost remains **$0**. No paid email, queue, scheduler, or cloud service is required by this sprint.

## Acceptance criteria

- an active-tenant owner can create an invitation for a normalized email address
- non-owners cannot create, list, or revoke tenant invitations
- only the authenticated account matching the invited email can accept
- successful acceptance creates exactly one `member` membership and consumes the invitation
- expired, revoked, consumed, malformed, and replayed invitations fail closed
- raw invitation tokens are not persisted
- direct membership addition invalidates redundant outstanding invitations for the same tenant/email
- invitation operations cannot expose or modify another tenant's records
- existing Sprint 68 membership/switching behavior remains green
- Python 3.12/3.14 quality/tests, wheel/package validation, Docker/Compose smoke, Trivy self-scan, and CodeQL are green before merge
