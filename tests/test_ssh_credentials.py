from __future__ import annotations

import base64
from pathlib import Path
import secrets
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from secscan.ssh_credentials import SshCredentialStore
from secscan.web import create_web_app


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _known_hosts(host: str = "server.example.com") -> str:
    public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return f"{host} {public_key}\n"


def test_credential_store_encrypts_secrets_and_returns_metadata_only(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    private_key = _private_key()
    known_hosts = _known_hosts()
    store = SshCredentialStore(database, _master_key())

    profile = store.create(
        name="Default Linux",
        username="secscan-audit",
        private_key=private_key,
        known_hosts=known_hosts,
        is_default=True,
    )

    assert profile.is_default is True
    assert profile.as_public_dict() == {
        "id": profile.id,
        "name": "Default Linux",
        "username": "secscan-audit",
        "is_default": True,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }
    raw = database.read_bytes()
    assert private_key.encode("utf-8") not in raw
    assert known_hosts.encode("utf-8") not in raw
    decrypted = store.decrypt(profile.id)
    assert decrypted.private_key == private_key
    assert decrypted.known_hosts == known_hosts


def test_default_and_host_binding_resolution(tmp_path: Path) -> None:
    store = SshCredentialStore(tmp_path / "jobs.db", _master_key())
    first = store.create(
        name="Default",
        username="audit",
        private_key=_private_key(),
        known_hosts=_known_hosts("default.example.com"),
        is_default=True,
    )
    second = store.create(
        name="Special host",
        username="special-audit",
        private_key=_private_key(),
        known_hosts=_known_hosts("special.example.com"),
    )

    assert store.resolve_profile_id("unbound.example.com") == first.id
    store.bind_host("special.example.com", second.id)
    assert store.resolve_profile_id("special.example.com") == second.id
    store.set_default(second.id)
    assert store.resolve_profile_id("unbound.example.com") == second.id
    assert sum(profile.is_default for profile in store.list()) == 1

    assert store.delete(second.id) is True
    assert store.resolve_profile_id("special.example.com") is None


def test_credential_api_never_returns_secret_material(monkeypatch, tmp_path: Path) -> None:
    master_key = _master_key()
    private_key = _private_key()
    known_hosts = _known_hosts()
    monkeypatch.setenv("SECSCAN_CREDENTIAL_KEY", master_key)
    client = TestClient(create_web_app(job_root=tmp_path / "jobs", runner=lambda _args: 0))

    created = client.post(
        "/api/v1/ssh-credentials",
        json={
            "name": "GUI Default",
            "username": "secscan-audit",
            "private_key": private_key,
            "known_hosts": known_hosts,
            "is_default": True,
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["name"] == "GUI Default"
    assert "private_key" not in body
    assert "known_hosts" not in body
    assert "ciphertext" not in str(body).lower()

    listed = client.get("/api/v1/ssh-credentials")
    assert listed.status_code == 200
    assert listed.json() == [body]
    assert private_key not in listed.text
    assert known_hosts not in listed.text

    with sqlite3.connect(tmp_path / "jobs" / "jobs.db") as connection:
        stored = connection.execute(
            "SELECT private_key_ciphertext, known_hosts_ciphertext FROM ssh_credential_profiles"
        ).fetchone()
    assert stored is not None
    assert private_key.encode("utf-8") not in bytes(stored[0])
    assert known_hosts.encode("utf-8") not in bytes(stored[1])


def test_invalid_master_key_fails_closed(tmp_path: Path) -> None:
    try:
        SshCredentialStore(tmp_path / "jobs.db", "not-a-fernet-key")
    except ValueError as exc:
        assert "SECSCAN_CREDENTIAL_KEY" in str(exc)
    else:
        raise AssertionError("invalid credential master key should fail closed")
