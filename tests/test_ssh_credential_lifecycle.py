from __future__ import annotations

import base64
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from secscan.auth import mount_auth
from secscan.credential_tenancy import SshCredentialTenantMiddleware
from secscan.service import create_app
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


def _known_hosts() -> str:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return f"127.0.0.1 {public_key}\n"


def _app(monkeypatch, tmp_path: Path):  # noqa: ANN001
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", _master_key())
    database = tmp_path / "jobs.db"
    root = tmp_path / "jobs"
    app = create_app(job_root=root, job_database=database, runner=lambda _args: 0)
    mount_auth(app, database=database)
    mount_web_ui(app, job_root=root, job_database=database)
    app.add_middleware(SshCredentialTenantMiddleware, database=database)
    return app


def test_owner_can_disable_credential_and_new_scan_fails_closed(monkeypatch, tmp_path: Path) -> None:
    client = TestClient(_app(monkeypatch, tmp_path))
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    )
    assert registered.status_code == 201
    created = client.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Production",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
            "is_default": True,
        },
    )
    assert created.status_code == 201, created.text
    profile_id = created.json()["id"]

    disabled = client.patch(
        f"/api/v1/ssh-credentials/{profile_id}/enabled", json={"enabled": False}
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json() == {"id": profile_id, "enabled": False}

    # Metadata remains available for history/administration.
    listed = client.get("/api/v1/ssh-credentials")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [profile_id]

    explicit = client.post(
        "/api/v1/linux-host-jobs",
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": profile_id,
        },
    )
    assert explicit.status_code == 422
    assert explicit.json()["detail"] == "SSH credential profile is disabled"

    # Disabling also removes implicit default/host selection for future scans.
    resolved = client.get("/api/v1/ssh-credentials/resolve", params={"host": "127.0.0.1"})
    assert resolved.status_code == 200
    assert resolved.json()["profile"] is None


def test_member_cannot_change_credential_enabled_state(monkeypatch, tmp_path: Path) -> None:
    app = _app(monkeypatch, tmp_path)
    owner = TestClient(app)
    member = TestClient(app)
    owner_user = owner.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    ).json()
    member.post(
        "/api/v1/auth/register",
        json={"email": "member@example.com", "password": "another correct horse battery staple"},
    )
    assert owner.post(
        "/api/v1/auth/tenants/current/members", json={"email": "member@example.com"}
    ).status_code == 201
    assert member.post(
        "/api/v1/auth/tenants/switch", json={"tenant_id": owner_user["tenant_id"]}
    ).status_code == 200
    profile_id = owner.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Shared",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
        },
    ).json()["id"]

    denied = member.patch(
        f"/api/v1/ssh-credentials/{profile_id}/enabled", json={"enabled": False}
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "tenant owner access required"
