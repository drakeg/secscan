from __future__ import annotations

from pathlib import Path
import sqlite3

from secscan.credential_tenancy import current_credential_tenant


class SshCredentialLifecycleStore:
    """Persist tenant-scoped credential availability without exposing secret material."""

    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ssh_credential_lifecycle (
                    tenant_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                    PRIMARY KEY (tenant_id, profile_id),
                    FOREIGN KEY (profile_id, tenant_id)
                        REFERENCES ssh_credential_profiles(id, tenant_id) ON DELETE CASCADE
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _tenant() -> str:
        return current_credential_tenant()

    def is_enabled(self, profile_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT enabled FROM ssh_credential_lifecycle WHERE tenant_id = ? AND profile_id = ?",
                (self._tenant(), profile_id),
            ).fetchone()
        return row is None or bool(row[0])

    def set_enabled(self, profile_id: str, enabled: bool) -> None:
        tenant_id = self._tenant()
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM ssh_credential_profiles WHERE tenant_id = ? AND id = ?",
                (tenant_id, profile_id),
            ).fetchone()
            if exists is None:
                raise ValueError("SSH credential profile was not found")
            connection.execute(
                """
                INSERT INTO ssh_credential_lifecycle (tenant_id, profile_id, enabled)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id, profile_id) DO UPDATE SET enabled = excluded.enabled
                """,
                (tenant_id, profile_id, 1 if enabled else 0),
            )
