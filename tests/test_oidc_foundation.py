from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from secscan.auth import AuthStore
from secscan.oidc import ExternalIdentityStore, OidcProviderConfig, normalize_oidc_issuer


def test_oidc_configuration_is_optional_and_never_exposes_client_secret() -> None:
    assert OidcProviderConfig.from_environment({}) is None

    config = OidcProviderConfig.from_environment(
        {
            "SECSCAN_OIDC_ISSUER": "https://login.example.com/tenant/",
            "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
            "SECSCAN_OIDC_CLIENT_SECRET": "super-secret",
        }
    )
    assert config is not None
    assert config.issuer == "https://login.example.com/tenant"
    assert config.client_id == "secscan-web"
    assert config.client_secret == "super-secret"
    assert config.public() == {
        "configured": True,
        "issuer": "https://login.example.com/tenant",
        "client_id": "secscan-web",
    }
    assert "super-secret" not in str(config.public())


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (
            {
                "SECSCAN_OIDC_ISSUER": "https://login.example.com",
                "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
            },
            "SECSCAN_OIDC_CLIENT_SECRET",
        ),
        (
            {
                "SECSCAN_OIDC_ISSUER": "http://login.example.com",
                "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
                "SECSCAN_OIDC_CLIENT_SECRET": "secret",
            },
            "OIDC issuer must use HTTPS",
        ),
        (
            {
                "SECSCAN_OIDC_ISSUER": "https://login.example.com?tenant=one",
                "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
                "SECSCAN_OIDC_CLIENT_SECRET": "secret",
            },
            "query or fragment",
        ),
    ],
)
def test_oidc_configuration_fails_closed(environment: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        OidcProviderConfig.from_environment(environment)


def test_insecure_oidc_issuer_is_limited_to_explicit_localhost_fixtures() -> None:
    assert (
        normalize_oidc_issuer(
            "http://127.0.0.1:8080/issuer/",
            allow_insecure_localhost=True,
        )
        == "http://127.0.0.1:8080/issuer"
    )
    with pytest.raises(ValueError, match="HTTPS"):
        normalize_oidc_issuer(
            "http://idp.example.com",
            allow_insecure_localhost=True,
        )


def test_external_identity_linkage_is_exact_and_does_not_use_email(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    first = auth.register("same-name@example.com", "correct horse battery staple")
    second = auth.register("second@example.com", "another correct horse battery staple")
    identities = ExternalIdentityStore(database)

    linked = identities.link(
        issuer="https://login.example.com/",
        subject="provider-subject-123",
        user_id=first.id,
    )
    assert linked.issuer == "https://login.example.com"
    assert linked.subject == "provider-subject-123"
    assert linked.user_id == first.id
    assert identities.resolve("https://login.example.com/", "provider-subject-123") == linked
    assert identities.resolve("https://login.example.com", "PROVIDER-SUBJECT-123") is None

    with pytest.raises(ValueError, match="already linked"):
        identities.link(
            issuer="https://login.example.com",
            subject="provider-subject-123",
            user_id=second.id,
        )

    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(auth_external_identities)"
            ).fetchall()
        }
    assert "email" not in columns


def test_external_identity_linkage_is_unique_per_issuer_and_local_user(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    user = AuthStore(database).register(
        "owner@example.com",
        "correct horse battery staple",
    )
    identities = ExternalIdentityStore(database)

    first = identities.link(
        issuer="https://login.example.com",
        subject="subject-one",
        user_id=user.id,
    )
    repeated = identities.link(
        issuer="https://login.example.com/",
        subject="subject-one",
        user_id=user.id,
    )
    assert repeated == first

    with pytest.raises(ValueError, match="already linked to this OIDC issuer"):
        identities.link(
            issuer="https://login.example.com",
            subject="subject-two",
            user_id=user.id,
        )

    second_issuer = identities.link(
        issuer="https://other-idp.example.com",
        subject="subject-two",
        user_id=user.id,
    )
    assert [item.issuer for item in identities.list_for_user(user.id)] == [
        "https://login.example.com",
        "https://other-idp.example.com",
    ]
    assert second_issuer.user_id == user.id


def test_external_identity_unlink_is_user_scoped(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    first = auth.register("first@example.com", "correct horse battery staple")
    second = auth.register("second@example.com", "another correct horse battery staple")
    identities = ExternalIdentityStore(database)
    identities.link(
        issuer="https://login.example.com",
        subject="subject-one",
        user_id=first.id,
    )

    assert (
        identities.unlink(
            issuer="https://login.example.com",
            subject="subject-one",
            user_id=second.id,
        )
        is False
    )
    assert identities.resolve("https://login.example.com", "subject-one") is not None
    assert (
        identities.unlink(
            issuer="https://login.example.com",
            subject="subject-one",
            user_id=first.id,
        )
        is True
    )
    assert identities.resolve("https://login.example.com", "subject-one") is None
