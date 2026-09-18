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
from secscan.tenant_api_keys import mount_tenant_api_keys
from secscan.web import mount_web_ui


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
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
    mount_tenant_api_keys(app, database=database)
    mount_web_ui(app, job_root=root, job_database=database)
    app.add_middleware(SshCredentialTenantMiddleware, database=database)
    return app


def test_member_api_key_uses_same_tenant_ssh_credential_without_admin_rights(
    monkeypatch, tmp_path: Path
) -> None:
    app = _app(monkeypatch, tmp_path)
    owner = TestClient(app)
    member = TestClient(app)

    owner_user = owner.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    ).json()
    member_user = member.post(
        "/api/v1/auth/register",
        json={"email": "member@example.com", "password": "another correct horse battery staple"},
    ).json()
    assert owner.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": "member@example.com"},
    ).status_code == 201
    assert member.post(
        "/api/v1/auth/tenants/switch",
        json={"tenant_id": owner_user["tenant_id"]},
    ).status_code == 200

    created = owner.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Shared",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
            "is_default": True,
        },
    )
    assert created.status_code == 201, created.text
    profile_id = created.json()["id"]

    api_key = owner.post(
        "/api/v1/auth/tenants/current/api-keys",
        json={"name": "member scanner", "principal_user_id": member_user["id"]},
    )
    assert api_key.status_code == 201, api_key.text
    secret = api_key.json()["secret"]
    headers = {"Authorization": f"Bearer {secret}"}

    member.cookies.clear()
    visible = member.get("/api/v1/ssh-credentials", headers=headers)
    assert visible.status_code == 200, visible.text
    assert [item["id"] for item in visible.json()] == [profile_id]

    submitted = member.post(
        "/api/v1/linux-host-jobs",
        headers=headers,
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": profile_id,
        },
    )
    assert submitted.status_code == 202, submitted.text

    denied = member.patch(
        f"/api/v1/ssh-credentials/{profile_id}/enabled",
        headers=headers,
        json={"enabled": False},
    )
    assert denied.status_code == 401
    assert denied.json()["detail"] == "session authentication required"


def test_api_key_cannot_cross_tenant_ssh_credential_boundary(monkeypatch, tmp_path: Path) -> None:
    app = _app(monkeypatch, tmp_path)
    first = TestClient(app)
    second = TestClient(app)

    first.post(
        "/api/v1/auth/register",
        json={"email": "first@example.com", "password": "correct horse battery staple"},
    )
    second.post(
        "/api/v1/auth/register",
        json={"email": "second@example.com", "password": "another correct horse battery staple"},
    )
    created = first.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "First tenant",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts(),
        },
    )
    assert created.status_code == 201
    first_profile_id = created.json()["id"]

    key = second.post(
        "/api/v1/auth/tenants/current/api-keys",
        json={"name": "second automation"},
    )
    assert key.status_code == 201
    secret = key.json()["secret"]
    second.cookies.clear()
    headers = {"Authorization": f"Bearer {secret}"}

    # A bearer key is authoritative even if another tenant's session cookie is present.
    assert first.get("/api/v1/ssh-credentials", headers=headers).json() == []
    assert second.get("/api/v1/ssh-credentials", headers=headers).json() == []
    rejected = second.post(
        "/api/v1/linux-host-jobs",
        headers=headers,
        json={
            "target": "127.0.0.1",
            "linux_host_authorized": True,
            "credential_profile_id": first_profile_id,
        },
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"] == "SSH credential profile was not found"
