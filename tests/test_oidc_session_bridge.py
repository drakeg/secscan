from __future__ import annotations

from pathlib import Path

import pytest

from secscan.auth import AuthStore
from secscan.oidc import (
    ExternalIdentityStore,
    VerifiedOidcIdentity,
    create_oidc_session,
)


def _stores(tmp_path: Path) -> tuple[AuthStore, ExternalIdentityStore]:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    identities = ExternalIdentityStore(database)
    return auth, identities


def test_oidc_session_uses_existing_local_session_semantics(tmp_path: Path) -> None:
    auth, identities = _stores(tmp_path)
    user = auth.register("owner@example.com", "a-secure-password")
    identities.link(
        issuer="https://login.example.com/tenant",
        subject="subject-123",
        user_id=user.id,
    )

    authenticated = create_oidc_session(
        VerifiedOidcIdentity(
            issuer="https://login.example.com/tenant",
            subject="subject-123",
        ),
        identity_store=identities,
        auth_store=auth,
    )

    assert authenticated.user_id == user.id
    session_user = auth.user_for_session(authenticated.session_token)
    assert session_user is not None
    assert session_user.id == user.id
    assert session_user.tenant_id == user.tenant_id


def test_oidc_session_fails_closed_for_unknown_external_subject(tmp_path: Path) -> None:
    auth, identities = _stores(tmp_path)
    auth.register("owner@example.com", "a-secure-password")

    with pytest.raises(ValueError, match="not linked"):
        create_oidc_session(
            VerifiedOidcIdentity(
                issuer="https://login.example.com/tenant",
                subject="unknown-subject",
            ),
            identity_store=identities,
            auth_store=auth,
        )


def test_oidc_session_fails_closed_for_disabled_local_user(tmp_path: Path) -> None:
    auth, identities = _stores(tmp_path)
    user = auth.register("owner@example.com", "a-secure-password")
    identities.link(
        issuer="https://login.example.com/tenant",
        subject="subject-123",
        user_id=user.id,
    )
    with auth._connect() as connection:
        connection.execute("UPDATE auth_users SET enabled = 0 WHERE id = ?", (user.id,))

    with pytest.raises(ValueError, match="unavailable"):
        create_oidc_session(
            VerifiedOidcIdentity(
                issuer="https://login.example.com/tenant",
                subject="subject-123",
            ),
            identity_store=identities,
            auth_store=auth,
        )


def test_oidc_session_does_not_infer_identity_from_email_or_tenant(tmp_path: Path) -> None:
    auth, identities = _stores(tmp_path)
    user = auth.register("subject-123@example.com", "a-secure-password")

    with pytest.raises(ValueError, match="not linked"):
        create_oidc_session(
            VerifiedOidcIdentity(
                issuer="https://login.example.com/tenant",
                subject=user.email,
            ),
            identity_store=identities,
            auth_store=auth,
        )


def test_oidc_session_fails_closed_if_home_tenant_membership_is_missing(tmp_path: Path) -> None:
    auth, identities = _stores(tmp_path)
    user = auth.register("owner@example.com", "a-secure-password")
    identities.link(
        issuer="https://login.example.com/tenant",
        subject="subject-123",
        user_id=user.id,
    )
    with auth._connect() as connection:
        connection.execute(
            "DELETE FROM auth_tenant_memberships WHERE tenant_id = ? AND user_id = ?",
            (user.tenant_id, user.id),
        )

    with pytest.raises(ValueError, match="unavailable"):
        create_oidc_session(
            VerifiedOidcIdentity(
                issuer="https://login.example.com/tenant",
                subject="subject-123",
            ),
            identity_store=identities,
            auth_store=auth,
        )
