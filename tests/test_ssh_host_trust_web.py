from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from secscan.auth import mount_auth
from secscan.ssh_host_trust import SshHostTrustStore
from secscan.ssh_host_trust_web import mount_ssh_host_trust


def _fingerprint(key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, api_token: str | None = None) -> TestClient:
    monkeypatch.setenv("SECSCAN_REGISTRATION_ENABLED", "true")
    database = tmp_path / "jobs.db"
    app = FastAPI()
    mount_ssh_host_trust(app, database=database)
    mount_auth(app, database=database, api_token=api_token)
    return TestClient(app)


def test_admin_discovers_approves_lists_and_deletes_host_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = base64.b64encode(b"web-host-key").decode("ascii")

    def fake_discover(self, host: str, port: int = 22):
        return self.record_discovery(host, port, [("ssh-ed25519", key, _fingerprint(key))])

    monkeypatch.setattr(SshHostTrustStore, "discover", fake_discover)
    client = _app(tmp_path, monkeypatch)
    registered = client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    assert registered.status_code == 201

    discovered = client.post(
        "/api/v1/admin/ssh-host-trust/discover", json={"host": "127.0.0.1", "port": 2222}
    )
    assert discovered.status_code == 200
    candidate = discovered.json()["discovered"][0]
    assert candidate["fingerprint"] == _fingerprint(key)
    assert discovered.json()["approved"] is None

    approved = client.post(
        "/api/v1/admin/ssh-host-trust/approve", json={"discovery_id": candidate["id"]}
    )
    assert approved.status_code == 200
    assert approved.json()["fingerprint"] == _fingerprint(key)
    assert approved.json()["approved_by"] == registered.json()["id"]

    listed = client.get("/api/v1/admin/ssh-host-trust")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert "private" not in listed.text.lower()

    removed = client.delete("/api/v1/admin/ssh-host-trust/127.0.0.1/2222")
    assert removed.status_code == 204
    assert client.get("/api/v1/admin/ssh-host-trust").json() == []


def test_non_admin_and_bearer_token_cannot_mutate_host_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "a" * 32
    client = _app(tmp_path, monkeypatch, api_token=token)
    client.post(
        "/api/v1/auth/register",
        json={"email": "admin@example.com", "password": "correct horse battery staple"},
    )
    client.post("/api/v1/auth/logout")
    client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "another correct horse battery staple"},
    )
    assert client.get("/api/v1/admin/ssh-host-trust").status_code == 403

    client.post("/api/v1/auth/logout")
    response = client.get(
        "/api/v1/admin/ssh-host-trust", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
