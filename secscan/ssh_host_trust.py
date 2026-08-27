from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import socket
import sqlite3
from uuid import uuid4

import paramiko

from secscan.scanners.network import validate_network_target

_DISCOVERY_TTL_MINUTES = 10
_MAX_KEY_TEXT = 16 * 1024


@dataclass(frozen=True)
class DiscoveredHostKey:
    id: str
    host: str
    port: int
    key_type: str
    key_base64: str
    fingerprint: str
    discovered_at: str
    expires_at: str

    def as_public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TrustedHostKey:
    host: str
    port: int
    key_type: str
    key_base64: str
    fingerprint: str
    approved_at: str
    approved_by: str

    def as_public_dict(self) -> dict[str, object]:
        return asdict(self)

    def known_hosts_line(self) -> str:
        token = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
        return f"{token} {self.key_type} {self.key_base64}\n"


def _timestamp() -> datetime:
    return datetime.now(UTC)


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    return port


def _fingerprint(key_base64: str) -> str:
    try:
        decoded = base64.b64decode(key_base64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("SSH host key contains invalid base64 data") from exc
    if not decoded:
        raise ValueError("SSH host key is empty")
    digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _validate_key(key_type: str, key_base64: str) -> tuple[str, str, str]:
    normalized_type = key_type.strip()
    normalized_key = key_base64.strip()
    if (
        not normalized_type
        or len(normalized_type) > 128
        or any(character.isspace() for character in normalized_type)
    ):
        raise ValueError("SSH host key type is invalid")
    if not (
        normalized_type.startswith("ssh-")
        or normalized_type.startswith("ecdsa-")
        or normalized_type.startswith("sk-")
    ):
        raise ValueError("SSH host key type is unsupported")
    if not normalized_key or len(normalized_key) > _MAX_KEY_TEXT:
        raise ValueError("SSH host key data is invalid")
    return normalized_type, normalized_key, _fingerprint(normalized_key)


def discover_host_keys(host: str, port: int = 22, timeout: int = 5) -> list[tuple[str, str, str]]:
    """Perform an unauthenticated SSH handshake and return the presented host key.

    Discovery is intentionally in-process. No request-derived host, port, or other
    value is passed to a command-line interpreter or external executable.
    """
    target = validate_network_target(host)
    validated_port = _validate_port(port)
    bounded_timeout = max(1, min(timeout, 10))
    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    try:
        sock = socket.create_connection((target, validated_port), timeout=bounded_timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=bounded_timeout)
        remote_key = transport.get_remote_server_key()
    except (OSError, EOFError, paramiko.SSHException) as exc:
        raise ValueError(f"SSH host-key discovery failed: {exc}") from exc
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()

    key_type, key_base64, fingerprint = _validate_key(remote_key.get_name(), remote_key.get_base64())
    return [(key_type, key_base64, fingerprint)]


class SshHostTrustStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def _migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ssh_host_key_discoveries (
                    id TEXT PRIMARY KEY,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    key_type TEXT NOT NULL,
                    key_base64 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ssh_host_key_discoveries_expiry_idx
                    ON ssh_host_key_discoveries(expires_at);
                CREATE TABLE IF NOT EXISTS ssh_trusted_host_keys (
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

    @staticmethod
    def _discovery(row: sqlite3.Row) -> DiscoveredHostKey:
        return DiscoveredHostKey(
            id=str(row["id"]),
            host=str(row["host"]),
            port=int(row["port"]),
            key_type=str(row["key_type"]),
            key_base64=str(row["key_base64"]),
            fingerprint=str(row["fingerprint"]),
            discovered_at=str(row["discovered_at"]),
            expires_at=str(row["expires_at"]),
        )

    @staticmethod
    def _trusted(row: sqlite3.Row) -> TrustedHostKey:
        return TrustedHostKey(
            host=str(row["host"]),
            port=int(row["port"]),
            key_type=str(row["key_type"]),
            key_base64=str(row["key_base64"]),
            fingerprint=str(row["fingerprint"]),
            approved_at=str(row["approved_at"]),
            approved_by=str(row["approved_by"]),
        )

    def record_discovery(self, host: str, port: int, keys: list[tuple[str, str, str]]) -> list[DiscoveredHostKey]:
        target = validate_network_target(host)
        validated_port = _validate_port(port)
        now = _timestamp()
        expires = now + timedelta(minutes=_DISCOVERY_TTL_MINUTES)
        records: list[DiscoveredHostKey] = []
        with self._connect() as connection:
            connection.execute("DELETE FROM ssh_host_key_discoveries WHERE expires_at <= ?", (now.isoformat(),))
            for key_type, key_base64, supplied_fingerprint in keys:
                normalized_type, normalized_key, fingerprint = _validate_key(key_type, key_base64)
                if supplied_fingerprint != fingerprint:
                    raise ValueError("SSH host-key fingerprint did not match the discovered key")
                record = DiscoveredHostKey(
                    id=str(uuid4()),
                    host=target,
                    port=validated_port,
                    key_type=normalized_type,
                    key_base64=normalized_key,
                    fingerprint=fingerprint,
                    discovered_at=now.isoformat(),
                    expires_at=expires.isoformat(),
                )
                connection.execute(
                    """INSERT INTO ssh_host_key_discoveries
                    (id, host, port, key_type, key_base64, fingerprint, discovered_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.id,
                        record.host,
                        record.port,
                        record.key_type,
                        record.key_base64,
                        record.fingerprint,
                        record.discovered_at,
                        record.expires_at,
                    ),
                )
                records.append(record)
        return records

    def discover(self, host: str, port: int = 22) -> list[DiscoveredHostKey]:
        return self.record_discovery(host, port, discover_host_keys(host, port))

    def approve(self, discovery_id: str, approved_by: str) -> TrustedHostKey:
        now = _timestamp()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ssh_host_key_discoveries WHERE id = ? AND expires_at > ?",
                (discovery_id, now.isoformat()),
            ).fetchone()
            if row is None:
                raise ValueError("SSH host-key discovery was not found or has expired")
            discovery = self._discovery(row)
            connection.execute(
                """INSERT INTO ssh_trusted_host_keys
                (host, port, key_type, key_base64, fingerprint, approved_at, approved_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host, port) DO UPDATE SET
                    key_type = excluded.key_type,
                    key_base64 = excluded.key_base64,
                    fingerprint = excluded.fingerprint,
                    approved_at = excluded.approved_at,
                    approved_by = excluded.approved_by
                """,
                (
                    discovery.host,
                    discovery.port,
                    discovery.key_type,
                    discovery.key_base64,
                    discovery.fingerprint,
                    now.isoformat(),
                    approved_by,
                ),
            )
            connection.execute(
                "DELETE FROM ssh_host_key_discoveries WHERE host = ? AND port = ?",
                (discovery.host, discovery.port),
            )
        trusted = self.get(discovery.host, discovery.port)
        assert trusted is not None
        return trusted

    def get(self, host: str, port: int = 22) -> TrustedHostKey | None:
        target = validate_network_target(host)
        validated_port = _validate_port(port)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ssh_trusted_host_keys WHERE host = ? AND port = ?",
                (target, validated_port),
            ).fetchone()
        return self._trusted(row) if row else None

    def list(self) -> list[TrustedHostKey]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ssh_trusted_host_keys ORDER BY host COLLATE NOCASE, port"
            ).fetchall()
        return [self._trusted(row) for row in rows]

    def delete(self, host: str, port: int = 22) -> bool:
        target = validate_network_target(host)
        validated_port = _validate_port(port)
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM ssh_trusted_host_keys WHERE host = ? AND port = ?",
                (target, validated_port),
            )
        return cursor.rowcount > 0
