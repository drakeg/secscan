from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sqlite3

from secscan.credential_tenancy import reset_credential_tenant, set_credential_tenant
from secscan.ssh_host_trust import SshHostTrustStore


def _key(seed: bytes) -> str:
    return base64.b64encode(seed).decode("ascii")


def _fingerprint(key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _approve(store: SshHostTrustStore, host: str, seed: bytes, approved_by: str) -> str:
    key = _key(seed)
    discovery = store.record_discovery(
        host, 22, [("ssh-ed25519", key, _fingerprint(key))]
    )[0]
    return store.approve(discovery.id, approved_by).fingerprint


def test_trust_discovery_approval_lookup_and_delete_are_tenant_scoped(tmp_path: Path) -> None:
    store = SshHostTrustStore(tmp_path / "jobs.db")

    first_token = set_credential_tenant("tenant-a")
    try:
        first_fingerprint = _approve(store, "127.0.0.1", b"tenant-a-key", "admin-a")
        assert store.get("127.0.0.1", 22) is not None
        assert [record.fingerprint for record in store.list()] == [first_fingerprint]
        foreign_discovery = store.record_discovery(
            "127.0.0.2",
            22,
            [("ssh-ed25519", _key(b"tenant-a-pending"), _fingerprint(_key(b"tenant-a-pending")))],
        )[0]
    finally:
        reset_credential_tenant(first_token)

    second_token = set_credential_tenant("tenant-b")
    try:
        assert store.get("127.0.0.1", 22) is None
        assert store.list() == []
        assert store.delete("127.0.0.1", 22) is False
        try:
            store.approve(foreign_discovery.id, "admin-b")
        except ValueError as exc:
            assert "not found or has expired" in str(exc)
        else:
            raise AssertionError("cross-tenant discovery approval should fail")

        second_fingerprint = _approve(store, "127.0.0.1", b"tenant-b-key", "admin-b")
        assert [record.fingerprint for record in store.list()] == [second_fingerprint]
    finally:
        reset_credential_tenant(second_token)

    first_token = set_credential_tenant("tenant-a")
    try:
        assert [record.fingerprint for record in store.list()] == [first_fingerprint]
        assert store.delete("127.0.0.1", 22) is True
        assert store.list() == []
    finally:
        reset_credential_tenant(first_token)


def test_legacy_host_trust_migrates_to_original_admin_tenant_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    key = _key(b"legacy-host-key")
    fingerprint = _fingerprint(key)
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
            CREATE TABLE ssh_host_key_discoveries (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                key_type TEXT NOT NULL,
                key_base64 TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE INDEX ssh_host_key_discoveries_expiry_idx
                ON ssh_host_key_discoveries(expires_at);
            CREATE TABLE ssh_trusted_host_keys (
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                key_type TEXT NOT NULL,
                key_base64 TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                PRIMARY KEY(host, port)
            );
            """
        )
        connection.execute(
            "INSERT INTO ssh_trusted_host_keys VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "127.0.0.1",
                22,
                "ssh-ed25519",
                key,
                fingerprint,
                "2026-08-02T00:00:00+00:00",
                "admin-id",
            ),
        )

    SshHostTrustStore(database)
    SshHostTrustStore(database)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT tenant_id, host, port, fingerprint FROM ssh_trusted_host_keys"
        ).fetchone()
    assert row == ("admin-tenant", "127.0.0.1", 22, fingerprint)

    token = set_credential_tenant("admin-tenant")
    try:
        trusted = SshHostTrustStore(database).get("127.0.0.1", 22)
        assert trusted is not None
        assert trusted.fingerprint == fingerprint
    finally:
        reset_credential_tenant(token)
