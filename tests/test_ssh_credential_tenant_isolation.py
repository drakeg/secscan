from __future__ import annotations

import base64
from pathlib import Path
import secrets
import sqlite3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from secscan.auth import mount_auth
from secscan.credential_tenancy import (
    SshCredentialTenantMiddleware,
    reset_credential_tenant,
    set_credential_tenant,
)
from secscan.service import create_app
from secscan.ssh_credentials import SshCredentialStore
from secscan.web import mount_web_ui


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _known_hosts(host: str) -> str:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return f"{host} {public_key}\n"


def _register(client: TestClient, email: str, password: str) -> dict[str, object]:
    response = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201
    return response.json()


def test_store_scopes_names_defaults_bindings_and_secret_lookup_by_tenant(tmp_path: Path) -> None:
    store = SshCredentialStore(tmp_path / "jobs.db", _master_key())

    first_token = set_credential_tenant("tenant-a")
    try:
        first = store.create(
            name="Shared name",
            username="audit-a",
            private_key=_private_key(),
            known_hosts=_known_hosts("first.example.com"),
            is_default=True,
        )
        store.bind_host("shared.example.com", first.id)
        assert store.resolve_profile_id("shared.example.com") == first.id
    finally:
        reset_credential_tenant(first_token)

    second_token = set_credential_tenant("tenant-b")
    try:
        assert store.list() == []
        assert store.get(first.id) is None
        try:
            store.decrypt(first.id)
        except ValueError as exc:
            assert "not found" in str(exc)
        else:
            raise AssertionError("cross-tenant secret lookup should fail")

        second = store.create(
            name="Shared name",
            username="audit-b",
            private_key=_private_key(),
            known_hosts=_known_hosts("second.example.com"),
            is_default=True,
        )
        assert store.resolve_profile_id("shared.example.com") == second.id
        store.bind_host("shared.example.com", second.id)
        assert store.resolve_profile_id("shared.example.com") == second.id
        assert store.delete(first.id) is False
    finally:
        reset_credential_tenant(second_token)

    first_token = set_credential_tenant("tenant-a")
    try:
        assert [profile.id for profile in store.list()] == [first.id]
        assert store.resolve_profile_id("shared.example.com") == first.id
    finally:
        reset_credential_tenant(first_token)


def test_legacy_credentials_migrate_to_original_admin_tenant_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    master_key = _master_key()
    fernet = Fernet(master_key.encode("ascii"))
    private_key = _private_key()
    known_hosts = _known_hosts("legacy.example.com")
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
            INSERT INTO auth_users VALUES (
                'admin-id', 'admin-tenant', 'admin@example.com', 'unused', 'admin', 1,
                '2026-08-01T00:00:00+00:00'
            );
            CREATE TABLE ssh_credential_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                private_key_ciphertext BLOB NOT NULL,
                known_hosts_ciphertext BLOB NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX ssh_credential_single_default_idx
                ON ssh_credential_profiles(is_default) WHERE is_default = 1;
            CREATE TABLE ssh_host_credentials (
                host TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL REFERENCES ssh_credential_profiles(id) ON DELETE CASCADE,
                updated_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """
            INSERT INTO ssh_credential_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-profile",
                "Legacy",
                "audit",
                fernet.encrypt(private_key.encode("utf-8")),
                fernet.encrypt(known_hosts.encode("utf-8")),
                1,
                "2026-08-02T00:00:00+00:00",
                "2026-08-02T00:00:00+00:00",
            ),
        )
        connection.execute(
            "INSERT INTO ssh_host_credentials VALUES (?, ?, ?)",
            ("legacy.example.com", "legacy-profile", "2026-08-02T00:00:00+00:00"),
        )

    SshCredentialStore(database, master_key)
    SshCredentialStore(database, master_key)

    with sqlite3.connect(database) as connection:
        profile_row = connection.execute(
            "SELECT tenant_id, id FROM ssh_credential_profiles"
        ).fetchone()
        binding_row = connection.execute(
            "SELECT tenant_id, host, profile_id FROM ssh_host_credentials"
        ).fetchone()
    assert profile_row == ("admin-tenant", "legacy-profile")
    assert binding_row == ("admin-tenant", "legacy.example.com", "legacy-profile")

    token = set_credential_tenant("admin-tenant")
    try:
        store = SshCredentialStore(database, master_key)
        assert store.resolve_profile_id("legacy.example.com") == "legacy-profile"
        assert store.decrypt("legacy-profile").private_key == private_key
    finally:
        reset_credential_tenant(token)


def test_authenticated_credential_api_does_not_cross_tenant_boundary(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", _master_key())
    database = tmp_path / "jobs.db"
    job_root = tmp_path / "jobs"
    app = create_app(job_root=job_root, job_database=database, runner=lambda _args: 0)
    mount_auth(app, database=database)
    mount_web_ui(app, job_root=job_root, job_database=database)
    app.add_middleware(SshCredentialTenantMiddleware, database=database)

    first = TestClient(app)
    second = TestClient(app)
    first_user = _register(first, "first@example.com", "correct horse battery staple")
    second_user = _register(second, "second@example.com", "another correct horse battery staple")
    assert first_user["tenant_id"] != second_user["tenant_id"]

    created = first.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Production",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts("server.example.com"),
            "is_default": True,
        },
    )
    assert created.status_code == 201
    first_profile_id = created.json()["id"]

    assert second.get("/api/v1/ssh-credentials").json() == []
    assert second.put(f"/api/v1/ssh-credentials/{first_profile_id}/default").status_code == 404
    assert second.delete(f"/api/v1/ssh-credentials/{first_profile_id}").status_code == 404

    second_created = second.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Production",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts("server.example.com"),
            "is_default": True,
        },
    )
    assert second_created.status_code == 201
    assert second_created.json()["id"] != first_profile_id
    assert [item["id"] for item in first.get("/api/v1/ssh-credentials").json()] == [first_profile_id]
    assert [item["id"] for item in second.get("/api/v1/ssh-credentials").json()] == [
        second_created.json()["id"]
    ]
