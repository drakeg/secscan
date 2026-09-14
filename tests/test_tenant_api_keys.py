from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from secscan.auth import AuthStore, User, mount_auth
from secscan.tenant_api_keys import TenantApiKeyStore, mount_tenant_api_keys


def _app(tmp_path: Path, monkeypatch) -> FastAPI:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    database = tmp_path / "jobs.db"
    app = FastAPI()
    mount_auth(app, database=database)
    mount_tenant_api_keys(app, database=database)

    @app.get("/api/v1/probe")
    def probe(request: Request) -> dict[str, str]:
        user = request.state.secscan_user
        return {"user_id": user.id, "tenant_id": user.tenant_id, "email": user.email}

    return app


def _register_owner(client: TestClient, email: str = "owner@example.com") -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple"},
    )
    assert response.status_code == 201
    return response.json()


def test_owner_creates_key_secret_once_and_digest_only_is_persisted(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    owner = _register_owner(client)

    created = client.post(
        "/api/v1/auth/tenants/current/api-keys",
        json={"name": "automation", "expires_in_days": 30},
    )
    assert created.status_code == 201
    document = created.json()
    secret = document["secret"]
    api_key = document["api_key"]
    assert secret.startswith("secscan_")
    assert api_key["tenant_id"] == owner["tenant_id"]
    assert api_key["principal_user_id"] == owner["id"]
    assert api_key["name"] == "automation"
    assert "secret" not in api_key

    listed = client.get("/api/v1/auth/tenants/current/api-keys")
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == api_key["id"]
    assert secret not in listed.text

    with sqlite3.connect(tmp_path / "jobs.db") as connection:
        row = connection.execute(
            "SELECT secret_digest, principal_user_id FROM tenant_api_keys WHERE id = ?", (api_key["id"],)
        ).fetchone()
    assert row is not None
    assert row[0] != secret
    assert len(row[0]) == 64
    assert row[1] == owner["id"]


def test_api_key_authenticates_to_exact_tenant_and_revocation_is_immediate(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    owner = _register_owner(client)
    created = client.post(
        "/api/v1/auth/tenants/current/api-keys",
        json={"name": "ci"},
    ).json()
    secret = created["secret"]
    key_id = created["api_key"]["id"]

    client.cookies.clear()
    probe = client.get("/api/v1/probe", headers={"Authorization": f"Bearer {secret}"})
    assert probe.status_code == 200
    assert probe.json()["tenant_id"] == owner["tenant_id"]
    assert probe.json()["user_id"] == owner["id"]

    assert client.get("/api/v1/auth/tenants/current/api-keys", headers={"Authorization": f"Bearer {secret}"}).status_code == 401

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    assert client.delete(f"/api/v1/auth/tenants/current/api-keys/{key_id}").status_code == 204

    client.cookies.clear()
    rejected = client.get("/api/v1/probe", headers={"Authorization": f"Bearer {secret}"})
    assert rejected.status_code == 401


def test_owner_can_bind_key_to_same_tenant_member_and_member_removal_invalidates_it(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", "correct horse battery staple")
    member_home = auth.register("member@example.com", "another correct horse battery staple")
    auth.add_tenant_member(owner.id, owner.tenant_id, member_home.email)
    store = TenantApiKeyStore(database)

    key, secret = store.create(
        actor=owner,
        name="member automation",
        principal_user_id=member_home.id,
    )
    assert key.created_by == owner.id
    assert key.principal_user_id == member_home.id

    authenticated = store.authenticate(secret)
    assert isinstance(authenticated, User)
    assert authenticated.id == member_home.id
    assert authenticated.tenant_id == owner.tenant_id

    auth.remove_tenant_member(owner.id, owner.tenant_id, member_home.id)
    assert store.authenticate(secret) is None


def test_cross_tenant_principal_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", "correct horse battery staple")
    outsider = auth.register("outsider@example.com", "another correct horse battery staple")
    store = TenantApiKeyStore(database)

    try:
        store.create(actor=owner, name="bad principal", principal_user_id=outsider.id)
    except ValueError as exc:
        assert str(exc) == "API key principal must be an enabled tenant member"
    else:
        raise AssertionError("cross-tenant principal unexpectedly accepted")


def test_invalid_tenant_key_does_not_fall_back_to_valid_session(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    _register_owner(client)

    session_probe = client.get("/api/v1/probe")
    assert session_probe.status_code == 200

    rejected = client.get(
        "/api/v1/probe",
        headers={"Authorization": "Bearer secscan_not-a-real-key.invalid"},
    )
    assert rejected.status_code == 401
    assert rejected.json()["detail"] == "invalid API key"


def test_expired_and_invalid_keys_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", "correct horse battery staple")
    store = TenantApiKeyStore(database)
    _, secret = store.create(actor=owner, name="short lived", expires_in_days=1)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE tenant_api_keys SET expires_at = ?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),),
        )

    assert store.authenticate(secret) is None
    assert store.authenticate("secscan_not-a-real-key.invalid") is None


def test_keys_are_tenant_scoped_and_cross_tenant_owner_cannot_revoke(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    first = auth.register("first@example.com", "correct horse battery staple")
    second = auth.register("second@example.com", "another correct horse battery staple")
    store = TenantApiKeyStore(database)
    key, secret = store.create(actor=first, name="first tenant")

    authenticated = store.authenticate(secret)
    assert isinstance(authenticated, User)
    assert authenticated.tenant_id == first.tenant_id
    assert authenticated.tenant_id != second.tenant_id

    try:
        store.revoke(actor=second, key_id=key.id)
    except ValueError as exc:
        assert str(exc) == "API key was not found"
    else:
        raise AssertionError("cross-tenant owner unexpectedly revoked API key")
    assert store.authenticate(secret) is not None


def test_non_owner_cannot_create_tenant_api_key(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    owner = auth.register("owner@example.com", "correct horse battery staple")
    member_home = auth.register("member@example.com", "another correct horse battery staple")
    auth.add_tenant_member(owner.id, owner.tenant_id, member_home.email)
    member = User(
        id=member_home.id,
        tenant_id=owner.tenant_id,
        email=member_home.email,
        role=member_home.role,
        enabled=True,
        created_at=member_home.created_at,
    )
    store = TenantApiKeyStore(database)

    try:
        store.create(actor=member, name="not allowed")
    except PermissionError as exc:
        assert str(exc) == "tenant owner access required"
    else:
        raise AssertionError("non-owner unexpectedly created API key")
