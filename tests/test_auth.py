from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from secscan.auth import AuthStore, hash_password, mount_auth, verify_password


def _app(tmp_path: Path, monkeypatch) -> FastAPI:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    app = FastAPI()

    @app.get("/api/v1/protected")
    def protected(request: Request) -> dict[str, str]:
        return {"email": request.state.secscan_user.email}

    mount_auth(app, database=tmp_path / "jobs.db")
    return app


def test_password_hash_is_salted_and_verifiable() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")
    assert first.startswith("scrypt$")
    assert first != second
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("wrong password", first)


def test_first_registration_is_admin_and_session_protects_routes(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "Admin@Example.COM", "password": "correct horse battery staple"},
    )
    assert response.status_code == 201
    assert response.json()["email"] == "admin@example.com"
    assert response.json()["role"] == "admin"
    assert "secscan_session" in client.cookies
    assert client.get("/api/v1/protected").json() == {"email": "admin@example.com"}
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert "password" not in me.text


def test_duplicate_registration_rejected_and_second_user_is_not_admin(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    payload = {"email": "one@example.com", "password": "correct horse battery staple"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    client.post("/api/v1/auth/logout")
    duplicate = client.post("/api/v1/auth/register", json=payload)
    assert duplicate.status_code == 422
    second = client.post(
        "/api/v1/auth/register",
        json={"email": "two@example.com", "password": "another correct horse battery staple"},
    )
    assert second.status_code == 201
    assert second.json()["role"] == "user"
    assert client.get("/api/v1/admin/users").status_code == 403


def test_login_logout_and_invalid_credentials(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    credentials = {"email": "admin@example.com", "password": "correct horse battery staple"}
    client.post("/api/v1/auth/register", json=credentials)
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/api/v1/protected").status_code == 401
    assert client.post("/api/v1/auth/login", json={**credentials, "password": "wrong"}).status_code == 401
    assert client.post("/api/v1/auth/login", json=credentials).status_code == 200
    assert client.get("/api/v1/protected").status_code == 200


def test_registration_can_be_disabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "false")
    app = FastAPI()
    mount_auth(app, database=tmp_path / "jobs.db")
    client = TestClient(app)
    assert client.get("/register").status_code == 404
    assert client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    ).status_code == 403


def test_admin_can_list_users_without_secret_fields(tmp_path: Path, monkeypatch) -> None:
    client = TestClient(_app(tmp_path, monkeypatch))
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    response = client.get("/api/v1/admin/users")
    assert response.status_code == 200
    assert response.json()[0]["role"] == "admin"
    assert "password" not in response.text
    assert "session" not in response.text


def test_session_tokens_are_stored_only_as_digests(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "jobs.db")
    user = store.register("admin@example.com", "correct horse battery staple")
    token = store.create_session(user.id)
    import sqlite3

    with sqlite3.connect(tmp_path / "jobs.db") as connection:
        stored = connection.execute("SELECT token_hash FROM auth_sessions").fetchone()[0]
    assert token != stored
    assert len(stored) == 64


def test_revoked_and_expired_sessions_fail_closed(tmp_path: Path) -> None:
    import sqlite3

    store = AuthStore(tmp_path / "jobs.db")
    user = store.register("session@example.com", "correct horse battery staple")
    revoked = store.create_session(user.id)
    assert store.user_for_session(revoked) is not None
    store.revoke_session(revoked)
    assert store.user_for_session(revoked) is None

    expired = store.create_session(user.id)
    with sqlite3.connect(tmp_path / "jobs.db") as connection:
        connection.execute(
            "UPDATE auth_sessions SET expires_at = ?",
            ("2000-01-01T00:00:00+00:00",),
        )
    assert store.user_for_session(expired) is None


def test_disabled_user_and_removed_membership_invalidate_existing_session(tmp_path: Path) -> None:
    import sqlite3

    store = AuthStore(tmp_path / "jobs.db")
    user = store.register("member@example.com", "correct horse battery staple")
    token = store.create_session(user.id)
    assert store.user_for_session(token) is not None

    with sqlite3.connect(tmp_path / "jobs.db") as connection:
        connection.execute("UPDATE auth_users SET enabled = 0 WHERE id = ?", (user.id,))
    assert store.user_for_session(token) is None

    with sqlite3.connect(tmp_path / "jobs.db") as connection:
        connection.execute("UPDATE auth_users SET enabled = 1 WHERE id = ?", (user.id,))
        connection.execute(
            "DELETE FROM auth_tenant_memberships WHERE tenant_id = ? AND user_id = ?",
            (user.tenant_id, user.id),
        )
    assert store.user_for_session(token) is None


def test_failed_tenant_switch_preserves_session_selection(tmp_path: Path) -> None:
    store = AuthStore(tmp_path / "jobs.db")
    user = store.register("owner@example.com", "correct horse battery staple")
    token = store.create_session(user.id)

    import pytest

    with pytest.raises(ValueError, match="tenant membership is required"):
        store.switch_session_tenant(token, "another-tenant")

    current = store.user_for_session(token)
    assert current is not None
    assert current.tenant_id == user.tenant_id
