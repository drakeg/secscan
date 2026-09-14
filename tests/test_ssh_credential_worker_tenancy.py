from __future__ import annotations

import base64
from pathlib import Path
import secrets
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from secscan.auth import mount_auth
from secscan.credential_tenancy import SshCredentialTenantMiddleware, current_credential_tenant
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


def test_linux_host_profile_worker_preserves_request_tenant(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", _master_key())
    database = tmp_path / "jobs.db"
    job_root = tmp_path / "jobs"
    app = create_app(job_root=job_root, job_database=database, runner=lambda _args: 0)
    mount_auth(app, database=database)
    mount_web_ui(app, job_root=job_root, job_database=database)
    app.add_middleware(SshCredentialTenantMiddleware, database=database)
    client = TestClient(app)

    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    )
    assert registered.status_code == 201
    tenant_id = registered.json()["tenant_id"]

    created = client.post(
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
    profile_id = created.json()["id"]

    observed_tenants: list[str] = []
    original_decrypt = SshCredentialStore.decrypt

    def tenant_checked_decrypt(self: SshCredentialStore, selected_profile_id: str):
        observed_tenants.append(current_credential_tenant())
        return original_decrypt(self, selected_profile_id)

    monkeypatch.setattr(SshCredentialStore, "decrypt", tenant_checked_decrypt)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr=""),
    )

    submitted = client.post(
        "/api/v1/linux-host-jobs",
        json={
            "target": "server.example.com",
            "linux_host_authorized": True,
            "credential_profile_id": profile_id,
        },
    )
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}")
        assert job.status_code == 200
        if job.json()["status"] in {"completed", "failed"}:
            break
        time.sleep(0.01)

    assert observed_tenants == [tenant_id]
    assert job.json()["status"] == "completed"
