from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

import secscan.ssh_host_trust as ssh_host_trust
from secscan.ssh_host_trust import SshHostTrustStore, discover_host_keys


def _key(seed: bytes) -> str:
    return base64.b64encode(seed).decode("ascii")


def _fingerprint(key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def test_discovery_uses_bounded_in_process_ssh_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _key(b"host-key-one")
    captured: dict[str, object] = {}

    class FakeSocket:
        def close(self) -> None:
            captured["socket_closed"] = True

    class FakeKey:
        def get_name(self) -> str:
            return "ssh-ed25519"

        def get_base64(self) -> str:
            return key

    class FakeTransport:
        def __init__(self, sock: object) -> None:
            captured["transport_socket"] = sock

        def start_client(self, *, timeout: int) -> None:
            captured["transport_timeout"] = timeout

        def get_remote_server_key(self) -> FakeKey:
            return FakeKey()

        def close(self) -> None:
            captured["transport_closed"] = True

    fake_socket = FakeSocket()

    def fake_create_connection(address, *, timeout):
        captured["address"] = address
        captured["socket_timeout"] = timeout
        return fake_socket

    monkeypatch.setattr(ssh_host_trust.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(ssh_host_trust.paramiko, "Transport", FakeTransport)

    discovered = discover_host_keys("127.0.0.1", 2222, timeout=5)

    assert captured["address"] == ("127.0.0.1", 2222)
    assert captured["socket_timeout"] == 5
    assert captured["transport_timeout"] == 5
    assert captured["transport_closed"] is True
    assert discovered == [("ssh-ed25519", key, _fingerprint(key))]


def test_discovery_bounds_timeout_before_network_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    key = _key(b"bounded-timeout-key")
    captured: dict[str, object] = {}

    class FakeSocket:
        def close(self) -> None:
            pass

    class FakeKey:
        def get_name(self) -> str:
            return "ssh-ed25519"

        def get_base64(self) -> str:
            return key

    class FakeTransport:
        def __init__(self, _sock: object) -> None:
            pass

        def start_client(self, *, timeout: int) -> None:
            captured["transport_timeout"] = timeout

        def get_remote_server_key(self) -> FakeKey:
            return FakeKey()

        def close(self) -> None:
            pass

    def fake_create_connection(address, *, timeout):
        captured["address"] = address
        captured["socket_timeout"] = timeout
        return FakeSocket()

    monkeypatch.setattr(ssh_host_trust.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(ssh_host_trust.paramiko, "Transport", FakeTransport)

    discover_host_keys("127.0.0.1", 22, timeout=999)

    assert captured["address"] == ("127.0.0.1", 22)
    assert captured["socket_timeout"] == 10
    assert captured["transport_timeout"] == 10


def test_trust_requires_exact_unexpired_discovery_and_replaces_only_explicitly(tmp_path: Path) -> None:
    store = SshHostTrustStore(tmp_path / "jobs.db")
    first_key = _key(b"first-host-key")
    second_key = _key(b"second-host-key")
    first = store.record_discovery(
        "127.0.0.1", 22, [("ssh-ed25519", first_key, _fingerprint(first_key))]
    )[0]
    trusted = store.approve(first.id, "admin-one")
    assert trusted.fingerprint == _fingerprint(first_key)
    assert trusted.approved_by == "admin-one"
    assert trusted.known_hosts_line() == f"127.0.0.1 ssh-ed25519 {first_key}\n"

    candidate = store.record_discovery(
        "127.0.0.1", 22, [("ssh-ed25519", second_key, _fingerprint(second_key))]
    )[0]
    assert store.get("127.0.0.1", 22).fingerprint == _fingerprint(first_key)  # type: ignore[union-attr]

    replaced = store.approve(candidate.id, "admin-two")
    assert replaced.fingerprint == _fingerprint(second_key)
    assert replaced.approved_by == "admin-two"


def test_nonstandard_port_uses_bracketed_known_hosts_token(tmp_path: Path) -> None:
    store = SshHostTrustStore(tmp_path / "jobs.db")
    key = _key(b"nonstandard-port-key")
    discovery = store.record_discovery(
        "127.0.0.1", 2222, [("ssh-ed25519", key, _fingerprint(key))]
    )[0]
    trusted = store.approve(discovery.id, "admin")
    assert trusted.known_hosts_line() == f"[127.0.0.1]:2222 ssh-ed25519 {key}\n"


def test_mismatched_fingerprint_and_unknown_discovery_fail_closed(tmp_path: Path) -> None:
    store = SshHostTrustStore(tmp_path / "jobs.db")
    key = _key(b"host-key")
    with pytest.raises(ValueError, match="fingerprint"):
        store.record_discovery("127.0.0.1", 22, [("ssh-ed25519", key, "SHA256:not-the-key")])
    with pytest.raises(ValueError, match="not found or has expired"):
        store.approve("missing", "admin")


def test_list_and_delete_trusted_hosts(tmp_path: Path) -> None:
    store = SshHostTrustStore(tmp_path / "jobs.db")
    key = _key(b"host-key")
    discovery = store.record_discovery(
        "127.0.0.1", 22, [("ssh-ed25519", key, _fingerprint(key))]
    )[0]
    store.approve(discovery.id, "admin")
    assert len(store.list()) == 1
    assert store.delete("127.0.0.1", 22)
    assert store.list() == []
    assert not store.delete("127.0.0.1", 22)
