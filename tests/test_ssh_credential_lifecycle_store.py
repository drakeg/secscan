from __future__ import annotations

import base64
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from secscan.credential_tenancy import reset_credential_tenant, set_credential_tenant
from secscan.ssh_credential_lifecycle import SshCredentialLifecycleStore
from secscan.ssh_credentials import SshCredentialStore


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


def test_lifecycle_state_is_tenant_scoped(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    credentials = SshCredentialStore(database, _master_key())
    token = set_credential_tenant("tenant-a")
    try:
        profile = credentials.create(
            name="Shared", username="audit", private_key=_private_key(), known_hosts=_known_hosts()
        )
    finally:
        reset_credential_tenant(token)

    lifecycle = SshCredentialLifecycleStore(database)
    assert lifecycle.is_enabled("tenant-a", profile.id) is True
    lifecycle.set_enabled("tenant-a", profile.id, False)
    assert lifecycle.is_enabled("tenant-a", profile.id) is False

    try:
        lifecycle.set_enabled("tenant-b", profile.id, False)
    except ValueError as exc:
        assert str(exc) == "SSH credential profile was not found"
    else:
        raise AssertionError("cross-tenant lifecycle mutation must fail closed")


def test_disabled_credential_is_blocked_by_core_store_operations(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    credentials = SshCredentialStore(database, _master_key())
    token = set_credential_tenant("tenant-a")
    try:
        profile = credentials.create(
            name="Shared",
            username="audit",
            private_key=_private_key(),
            known_hosts=_known_hosts(),
            is_default=True,
        )
        credentials.bind_host("127.0.0.1", profile.id)
        lifecycle = SshCredentialLifecycleStore(database)
        lifecycle.set_enabled("tenant-a", profile.id, False)

        assert credentials.resolve_profile_id("127.0.0.1") is None

        for action in (
            lambda: credentials.decrypt(profile.id),
            lambda: credentials.set_default(profile.id),
            lambda: credentials.bind_host("127.0.0.2", profile.id),
        ):
            try:
                action()
            except ValueError as exc:
                assert str(exc) == "SSH credential profile is disabled"
            else:
                raise AssertionError("disabled SSH credential unexpectedly remained usable")
    finally:
        reset_credential_tenant(token)
