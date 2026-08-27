from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from secscan.ssh_credentials import SshCredentialStore
from secscan.ssh_host_trust import SshHostTrustStore


def _master_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _private_key() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _fingerprint(key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def test_approved_global_host_key_is_merged_into_ephemeral_profile_known_hosts(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    manual_key = base64.b64encode(b"manual-key").decode("ascii")
    manual_hosts = f"manual.example.com ssh-ed25519 {manual_key}\n"
    credentials = SshCredentialStore(database, _master_key())
    profile = credentials.create(
        name="Linux",
        username="audit",
        private_key=_private_key(),
        known_hosts=manual_hosts,
    )

    trusted_key = base64.b64encode(b"approved-key").decode("ascii")
    trust = SshHostTrustStore(database)
    discovery = trust.record_discovery(
        "127.0.0.1", 2222, [("ssh-ed25519", trusted_key, _fingerprint(trusted_key))]
    )[0]
    trust.approve(discovery.id, "admin")

    decrypted = credentials.decrypt(profile.id)
    assert manual_hosts in decrypted.known_hosts
    assert f"[127.0.0.1]:2222 ssh-ed25519 {trusted_key}\n" in decrypted.known_hosts
    assert "approved-key" not in database.read_text(encoding="utf-8", errors="ignore")
