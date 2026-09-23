from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from secscan import auth
from secscan.auth import AuthStore, SESSION_COOKIE, mount_auth
from secscan.oidc import (
    ExternalIdentityStore,
    OidcDiscoveryDocument,
    OidcProviderConfig,
    OidcTokenResponse,
    VerifiedOidcIdentity,
)


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECSCAN_OIDC_ISSUER", "https://login.example.com/tenant")
    monkeypatch.setenv("SECSCAN_OIDC_CLIENT_ID", "secscan-web")
    monkeypatch.setenv("SECSCAN_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv(
        "SECSCAN_OIDC_REDIRECT_URI",
        "https://secscan.example.com/api/v1/auth/oidc/callback",
    )


def _discovery(config: OidcProviderConfig) -> OidcDiscoveryDocument:
    return OidcDiscoveryDocument.from_mapping(
        config,
        {
            "issuer": config.issuer,
            "authorization_endpoint": "https://login.example.com/oauth2/authorize",
            "token_endpoint": "https://login.example.com/oauth2/token",
            "jwks_uri": "https://login.example.com/oauth2/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
    )


def test_oidc_configuration_requires_explicit_https_redirect_uri(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.delenv("SECSCAN_OIDC_REDIRECT_URI")
    with pytest.raises(ValueError, match="REDIRECT_URI"):
        mount_auth(FastAPI(), database=tmp_path / "jobs.db")

    monkeypatch.setenv("SECSCAN_OIDC_REDIRECT_URI", "http://secscan.example.com/callback")
    with pytest.raises(ValueError, match="absolute HTTPS"):
        mount_auth(FastAPI(), database=tmp_path / "jobs2.db")


def test_oidc_login_is_public_and_redirects_to_validated_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(
        auth,
        "fetch_oidc_discovery",
        lambda config: _discovery(config),
        raising=False,
    )
    app = FastAPI()
    mount_auth(app, database=tmp_path / "jobs.db")
    client = TestClient(app)

    response = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    parsed = urlsplit(location)
    assert parsed.hostname == "login.example.com"
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["secscan-web"]
    assert query["redirect_uri"] == [
        "https://secscan.example.com/api/v1/auth/oidc/callback"
    ]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid"]
    assert query["state"][0]
    assert query["nonce"][0]


def test_oidc_callback_creates_existing_session_only_after_verified_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    database = tmp_path / "jobs.db"
    local = AuthStore(database)
    user = local.register("owner@example.com", "a-secure-password")
    identities = ExternalIdentityStore(database)
    identities.link(
        issuer="https://login.example.com/tenant",
        subject="subject-123",
        user_id=user.id,
    )

    monkeypatch.setattr(auth, "fetch_oidc_discovery", lambda config: _discovery(config), raising=False)
    monkeypatch.setattr(
        auth,
        "exchange_oidc_code",
        lambda *_args, **_kwargs: OidcTokenResponse(id_token="signed-token"),
        raising=False,
    )
    monkeypatch.setattr(auth, "fetch_oidc_jwks", lambda _discovery: {"keys": [{}]}, raising=False)
    monkeypatch.setattr(
        auth,
        "verify_oidc_id_token",
        lambda *_args, **_kwargs: VerifiedOidcIdentity(
            issuer="https://login.example.com/tenant",
            subject="subject-123",
        ),
        raising=False,
    )

    app = FastAPI()
    mount_auth(app, database=database)
    client = TestClient(app)

    login = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    callback = client.get(
        "/api/v1/auth/oidc/callback",
        params={"state": state, "code": "authorization-code"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/app"
    assert SESSION_COOKIE in callback.cookies
    session_user = local.user_for_session(callback.cookies[SESSION_COOKIE])
    assert session_user is not None
    assert session_user.id == user.id
    assert session_user.tenant_id == user.tenant_id


def test_oidc_callback_burns_state_before_downstream_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(auth, "fetch_oidc_discovery", lambda config: _discovery(config), raising=False)
    monkeypatch.setattr(
        auth,
        "exchange_oidc_code",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("provider failed")),
        raising=False,
    )
    app = FastAPI()
    mount_auth(app, database=tmp_path / "jobs.db")
    client = TestClient(app)

    login = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    first = client.get(
        "/api/v1/auth/oidc/callback",
        params={"state": state, "code": "authorization-code"},
    )
    assert first.status_code == 401

    second = client.get(
        "/api/v1/auth/oidc/callback",
        params={"state": state, "code": "authorization-code"},
    )
    assert second.status_code == 401


def test_oidc_callback_rejects_provider_error_and_missing_parameters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    app = FastAPI()
    mount_auth(app, database=tmp_path / "jobs.db")
    client = TestClient(app)

    assert client.get(
        "/api/v1/auth/oidc/callback",
        params={"error": "access_denied"},
    ).status_code == 401
    assert client.get("/api/v1/auth/oidc/callback").status_code == 400


def test_oidc_routes_are_not_available_when_unconfigured(tmp_path: Path) -> None:
    app = FastAPI()
    mount_auth(app, database=tmp_path / "jobs.db")
    client = TestClient(app)

    assert client.get("/api/v1/auth/oidc/login").status_code == 404
    assert client.get("/api/v1/auth/oidc/callback").status_code == 404
