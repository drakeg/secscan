from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import os
from pathlib import Path
import sqlite3
from collections.abc import Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class OidcProviderConfig:
    issuer: str
    client_id: str
    client_secret: str

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        allow_insecure_localhost: bool = False,
    ) -> OidcProviderConfig | None:
        source = os.environ if environment is None else environment
        issuer = source.get("SECSCAN_OIDC_ISSUER", "").strip()
        client_id = source.get("SECSCAN_OIDC_CLIENT_ID", "").strip()
        client_secret = source.get("SECSCAN_OIDC_CLIENT_SECRET", "")

        if not issuer and not client_id and not client_secret:
            return None

        missing = [
            name
            for name, value in (
                ("SECSCAN_OIDC_ISSUER", issuer),
                ("SECSCAN_OIDC_CLIENT_ID", client_id),
                ("SECSCAN_OIDC_CLIENT_SECRET", client_secret),
            )
            if not value
        ]
        if missing:
            raise ValueError("OIDC configuration is incomplete; missing " + ", ".join(missing))

        if len(client_id) > 512:
            raise ValueError("SECSCAN_OIDC_CLIENT_ID must not exceed 512 characters")
        if len(client_secret) > 4096:
            raise ValueError("SECSCAN_OIDC_CLIENT_SECRET must not exceed 4096 characters")

        return cls(
            issuer=normalize_oidc_issuer(
                issuer,
                allow_insecure_localhost=allow_insecure_localhost,
            ),
            client_id=client_id,
            client_secret=client_secret,
        )

    def public(self) -> dict[str, object]:
        return {
            "configured": True,
            "issuer": self.issuer,
            "client_id": self.client_id,
        }


@dataclass(frozen=True)
class ExternalIdentity:
    issuer: str
    subject: str
    user_id: str
    linked_at: str

    def public(self) -> dict[str, str]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "user_id": self.user_id,
            "linked_at": self.linked_at,
        }


def normalize_oidc_issuer(value: str, *, allow_insecure_localhost: bool = False) -> str:
    issuer = value.strip()
    if not issuer:
        raise ValueError("OIDC issuer is required")
    if len(issuer) > 2048:
        raise ValueError("OIDC issuer must not exceed 2048 characters")

    parsed = urlsplit(issuer)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("OIDC issuer must not contain user information")
    if parsed.query or parsed.fragment:
        raise ValueError("OIDC issuer must not contain a query or fragment")
    if not parsed.hostname:
        raise ValueError("OIDC issuer must be an absolute URL")

    local_http_allowed = (
        allow_insecure_localhost
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if parsed.scheme != "https" and not local_http_allowed:
        raise ValueError("OIDC issuer must use HTTPS")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OIDC issuer port is invalid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("OIDC issuer port is invalid")

    return issuer


def _validate_subject(subject: str) -> str:
    if not subject:
        raise ValueError("OIDC subject is required")
    if len(subject) > 1024:
        raise ValueError("OIDC subject must not exceed 1024 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in subject):
        raise ValueError("OIDC subject must not contain control characters")
    return subject


class ExternalIdentityStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_external_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (issuer, subject),
                    UNIQUE (user_id, issuer)
                );
                CREATE INDEX IF NOT EXISTS auth_external_identities_user_idx
                    ON auth_external_identities(user_id);
                """
            )

    def link(self, *, issuer: str, subject: str, user_id: str) -> ExternalIdentity:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        now = datetime.now(UTC).isoformat()

        with self._connect() as connection:
            user = connection.execute(
                "SELECT 1 FROM auth_users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if user is None:
                raise ValueError("local user was not found")

            existing = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE issuer = ? AND subject = ?
                """,
                (normalized_issuer, validated_subject),
            ).fetchone()
            if existing is not None:
                if str(existing["user_id"]) != user_id:
                    raise ValueError("external identity is already linked")
                return _identity(existing)

            existing_user = connection.execute(
                """
                SELECT 1 FROM auth_external_identities
                WHERE issuer = ? AND user_id = ?
                """,
                (normalized_issuer, user_id),
            ).fetchone()
            if existing_user is not None:
                raise ValueError("local user is already linked to this OIDC issuer")

            connection.execute(
                """
                INSERT INTO auth_external_identities (issuer, subject, user_id, linked_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized_issuer, validated_subject, user_id, now),
            )

        identity = self.resolve(normalized_issuer, validated_subject)
        assert identity is not None
        return identity

    def resolve(self, issuer: str, subject: str) -> ExternalIdentity | None:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE issuer = ? AND subject = ?
                """,
                (normalized_issuer, validated_subject),
            ).fetchone()
        return _identity(row) if row is not None else None

    def list_for_user(self, user_id: str) -> list[ExternalIdentity]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE user_id = ?
                ORDER BY issuer, subject
                """,
                (user_id,),
            ).fetchall()
        return [_identity(row) for row in rows]

    def unlink(self, *, issuer: str, subject: str, user_id: str) -> bool:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM auth_external_identities
                WHERE issuer = ? AND subject = ? AND user_id = ?
                """,
                (normalized_issuer, validated_subject, user_id),
            )
        return cursor.rowcount == 1


def _identity(row: sqlite3.Row) -> ExternalIdentity:
    return ExternalIdentity(
        issuer=str(row["issuer"]),
        subject=str(row["subject"]),
        user_id=str(row["user_id"]),
        linked_at=str(row["linked_at"]),
    )
