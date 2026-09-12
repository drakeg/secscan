from __future__ import annotations

from pathlib import Path
import sqlite3

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from secscan.auth import AuthStore, mount_auth


PASSWORD = "correct horse battery staple"


def _app(tmp_path: Path, monkeypatch) -> FastAPI:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    app = FastAPI()

    @app.get("/api/v1/current-tenant")
    def current_tenant(request: Request) -> dict[str, str]:
        return {
            "user_id": request.state.secscan_user.id,
            "tenant_id": request.state.secscan_user.tenant_id,
        }

    mount_auth(app, database=tmp_path / "jobs.db")
    return app


def _register(client: TestClient, email: str) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 201
    return response.json()


def test_existing_account_can_join_and_switch_tenants(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    owner_client = TestClient(app)
    member_client = TestClient(app)

    owner = _register(owner_client, "owner@example.com")
    member = _register(member_client, "member@example.com")
    owner_tenant = str(owner["tenant_id"])
    member_home_tenant = str(member["tenant_id"])

    added = owner_client.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": "MEMBER@example.com"},
    )
    assert added.status_code == 201
    assert added.json()["tenant_id"] == owner_tenant
    assert added.json()["role"] == "member"

    memberships = member_client.get("/api/v1/auth/tenants")
    assert memberships.status_code == 200
    assert {(item["tenant_id"], item["role"]) for item in memberships.json()} == {
        (member_home_tenant, "owner"),
        (owner_tenant, "member"),
    }

    switched = member_client.post(
        "/api/v1/auth/tenants/switch",
        json={"tenant_id": owner_tenant},
    )
    assert switched.status_code == 200
    assert switched.json()["tenant_id"] == owner_tenant
    assert member_client.get("/api/v1/current-tenant").json()["tenant_id"] == owner_tenant


def test_switch_rejects_tenant_without_membership(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    first = TestClient(app)
    second = TestClient(app)
    _register(first, "first@example.com")
    second_user = _register(second, "second@example.com")

    response = first.post(
        "/api/v1/auth/tenants/switch",
        json={"tenant_id": second_user["tenant_id"]},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant membership is required"


def test_non_owner_cannot_change_membership(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    owner_client = TestClient(app)
    member_client = TestClient(app)
    third_client = TestClient(app)

    owner = _register(owner_client, "owner@example.com")
    member = _register(member_client, "member@example.com")
    _register(third_client, "third@example.com")
    owner_tenant = str(owner["tenant_id"])

    assert owner_client.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": member["email"]},
    ).status_code == 201
    assert member_client.post(
        "/api/v1/auth/tenants/switch", json={"tenant_id": owner_tenant}
    ).status_code == 200

    forbidden = member_client.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": "third@example.com"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"] == "tenant owner access required"


def test_removing_active_member_invalidates_session_fail_closed(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    owner_client = TestClient(app)
    member_client = TestClient(app)

    owner = _register(owner_client, "owner@example.com")
    member = _register(member_client, "member@example.com")
    owner_tenant = str(owner["tenant_id"])

    assert owner_client.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": member["email"]},
    ).status_code == 201
    assert member_client.post(
        "/api/v1/auth/tenants/switch", json={"tenant_id": owner_tenant}
    ).status_code == 200

    removed = owner_client.delete(
        f"/api/v1/auth/tenants/current/members/{member['id']}"
    )
    assert removed.status_code == 204
    assert member_client.get("/api/v1/current-tenant").status_code == 401


def test_owner_cannot_remove_self(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    owner = _register(client, "owner@example.com")

    response = client.delete(
        f"/api/v1/auth/tenants/current/members/{owner['id']}"
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "owners cannot remove themselves"


def test_legacy_accounts_migrate_to_owner_membership(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    user_id = "legacy-user"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE auth_users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE auth_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """INSERT INTO auth_users
               (id, tenant_id, email, password_hash, role, enabled, created_at)
               VALUES (?, ?, ?, 'unused', 'admin', 1, ?)""",
            (user_id, user_id, "legacy@example.com", "2026-01-01T00:00:00+00:00"),
        )

    store = AuthStore(database)
    memberships = store.list_memberships(user_id)
    assert len(memberships) == 1
    assert memberships[0].tenant_id == user_id
    assert memberships[0].role == "owner"

    with sqlite3.connect(database) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(auth_sessions)").fetchall()
        }
    assert "active_tenant_id" in columns
