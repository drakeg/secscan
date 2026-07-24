from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ScanHistoryEntry:
    id: int
    created_at: str
    scanner: str
    target: str
    duration_ms: int
    fail_on: str
    critical: int
    high: int
    medium: int
    low: int
    unknown: int
    report_path: str
    sbom_path: str
    diff_path: str | None
    secscan_version: str
    scanner_version: str


class HistoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"
            )
            applied = {
                int(row["version"])
                for row in connection.execute("SELECT version FROM schema_migrations")
            }
            if 1 not in applied:
                connection.executescript(
                    """
                    CREATE TABLE scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        scanner TEXT NOT NULL,
                        target TEXT NOT NULL,
                        duration_ms INTEGER NOT NULL,
                        fail_on TEXT NOT NULL,
                        critical INTEGER NOT NULL,
                        high INTEGER NOT NULL,
                        medium INTEGER NOT NULL,
                        low INTEGER NOT NULL,
                        unknown INTEGER NOT NULL,
                        report_path TEXT NOT NULL,
                        sbom_path TEXT NOT NULL,
                        diff_path TEXT,
                        secscan_version TEXT NOT NULL,
                        scanner_version TEXT NOT NULL
                    );
                    CREATE INDEX scans_target_created_at_idx
                        ON scans(target, created_at DESC);
                    """
                )
                connection.execute("INSERT INTO schema_migrations(version) VALUES (1)")

    def record_scan(
        self,
        *,
        scanner: str,
        target: str,
        duration_ms: int,
        fail_on: str,
        summary: dict[str, Any],
        report_path: Path,
        sbom_path: Path,
        diff_path: Path | None,
        secscan_version: str,
        scanner_version: str,
    ) -> int:
        self.migrate()
        severity = summary.get("by_severity", {})
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    scanner, target, duration_ms, fail_on,
                    critical, high, medium, low, unknown,
                    report_path, sbom_path, diff_path,
                    secscan_version, scanner_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scanner,
                    target,
                    duration_ms,
                    fail_on,
                    int(severity.get("CRITICAL", 0)),
                    int(severity.get("HIGH", 0)),
                    int(severity.get("MEDIUM", 0)),
                    int(severity.get("LOW", 0)),
                    int(severity.get("UNKNOWN", 0)),
                    str(report_path),
                    str(sbom_path),
                    str(diff_path) if diff_path else None,
                    secscan_version,
                    scanner_version,
                ),
            )
            return int(cursor.lastrowid)

    def list_scans(self, limit: int = 20) -> list[ScanHistoryEntry]:
        self.migrate()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._entry(row) for row in rows]

    def get_scan(self, scan_id: int) -> ScanHistoryEntry | None:
        self.migrate()
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._entry(row) if row else None

    @staticmethod
    def _entry(row: sqlite3.Row) -> ScanHistoryEntry:
        return ScanHistoryEntry(**dict(row))
