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


def test_tenant_member_can_read_but_not_administer_shared_ssh_credentials(
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

    owner = TestClient(app)
    member = TestClient(app)
    owner_user = _register(owner, "owner@example.com", "correct horse battery staple")
    _register(member, "member@example.com", "another correct horse battery staple")

    added = owner.post(
        "/api/v1/auth/tenants/current/members",
        json={"email": "member@example.com"},
    )
    assert added.status_code == 201, added.text
    switched = member.post(
        "/api/v1/auth/tenants/switch",
        json={"tenant_id": owner_user["tenant_id"]},
    )
    assert switched.status_code == 200, switched.text

    created = owner.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Production",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts("127.0.0.1"),
            "is_default": True,
        },
    )
    assert created.status_code == 201, created.text
    profile_id = created.json()["id"]

    visible = member.get("/api/v1/ssh-credentials")
    assert visible.status_code == 200
    assert [item["id"] for item in visible.json()] == [profile_id]

    denied_create = member.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "Member credential",
            "username": "audit",
            "private_key": _private_key(),
            "known_hosts": _known_hosts("127.0.0.1"),
        },
    )
    assert denied_create.status_code == 403
    assert denied_create.json()["detail"] == "tenant owner access required"

    denied_default = member.put(f"/api/v1/ssh-credentials/{profile_id}/default")
    assert denied_default.status_code == 403
    denied_delete = member.delete(f"/api/v1/ssh-credentials/{profile_id}")
    assert denied_delete.status_code == 403

    assert owner.get("/api/v1/ssh-credentials").json()[0]["id"] == profile_id
