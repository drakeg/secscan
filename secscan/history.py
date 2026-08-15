from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secscan.compare import finding_fingerprint
from secscan.models import Finding

SCHEMA_VERSION = 2


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
    findings_recorded: int


@dataclass(frozen=True)
class StoredFinding:
    fingerprint: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: str
    target: str
    package_type: str | None


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
            if 2 not in applied:
                columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(scans)")
                }
                if "findings_recorded" not in columns:
                    connection.execute(
                        "ALTER TABLE scans ADD COLUMN findings_recorded INTEGER NOT NULL DEFAULT 0"
                    )
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS scan_findings (
                        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        fingerprint TEXT NOT NULL,
                        vulnerability_id TEXT NOT NULL,
                        package_name TEXT NOT NULL,
                        installed_version TEXT NOT NULL,
                        fixed_version TEXT,
                        severity TEXT NOT NULL,
                        target TEXT NOT NULL,
                        package_type TEXT,
                        PRIMARY KEY (scan_id, fingerprint)
                    );
                    CREATE INDEX IF NOT EXISTS scan_findings_fingerprint_idx
                        ON scan_findings(fingerprint, scan_id);
                    """
                )
                connection.execute("INSERT INTO schema_migrations(version) VALUES (2)")

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
        findings: tuple[Finding, ...] | None = None,
    ) -> int:
        self.migrate()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    scanner, target, duration_ms, fail_on,
                    critical, high, medium, low, unknown,
                    report_path, sbom_path, diff_path,
                    secscan_version, scanner_version, findings_recorded
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scanner,
                    target,
                    duration_ms,
                    fail_on,
                    int(summary.get("CRITICAL", 0)),
                    int(summary.get("HIGH", 0)),
                    int(summary.get("MEDIUM", 0)),
                    int(summary.get("LOW", 0)),
                    int(summary.get("UNKNOWN", 0)),
                    str(report_path),
                    str(sbom_path),
                    str(diff_path) if diff_path else None,
                    secscan_version,
                    scanner_version,
                    int(findings is not None),
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not return a scan history ID")
            scan_id = cursor.lastrowid
            if findings is not None:
                rows = [
                    (
                        scan_id,
                        finding_fingerprint(finding),
                        finding.vulnerability_id,
                        finding.package_name,
                        finding.installed_version,
                        finding.fixed_version,
                        finding.severity,
                        finding.target,
                        finding.package_type,
                    )
                    for finding in findings
                ]
                if len({row[1] for row in rows}) != len(rows):
                    raise ValueError("scan contains duplicate finding fingerprints")
                connection.executemany(
                    """
                    INSERT INTO scan_findings (
                        scan_id, fingerprint, vulnerability_id, package_name,
                        installed_version, fixed_version, severity, target, package_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
            return scan_id

    def latest_finding_observations(
        self, *, scanner: str, target: str
    ) -> list[tuple[ScanHistoryEntry, tuple[StoredFinding, ...]]]:
        return self.list_finding_observations(scanner=scanner, target=target, limit=2)

    def list_finding_observations(
        self, *, scanner: str, target: str, limit: int
    ) -> list[tuple[ScanHistoryEntry, tuple[StoredFinding, ...]]]:
        if limit < 1:
            raise ValueError("finding history limit must be at least 1")
        self.migrate()
        with self._connect() as connection:
            scans = connection.execute(
                """
                SELECT * FROM scans
                WHERE scanner = ? AND target = ? AND findings_recorded = 1
                ORDER BY id DESC
                LIMIT ?
                """,
                (scanner, target, limit),
            ).fetchall()
            scans.reverse()
            observations = []
            for scan in scans:
                rows = connection.execute(
                    """
                    SELECT fingerprint, vulnerability_id, package_name, installed_version,
                           fixed_version, severity, target, package_type
                    FROM scan_findings
                    WHERE scan_id = ?
                    ORDER BY fingerprint
                    """,
                    (scan["id"],),
                ).fetchall()
                observations.append(
                    (self._entry(scan), tuple(StoredFinding(**dict(row)) for row in rows))
                )
        return observations

    def list_scans(self, limit: int = 20) -> list[ScanHistoryEntry]:
        if limit < 1:
            raise ValueError("history limit must be at least 1")
        self.migrate()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._entry(row) for row in rows]

    def list_trend_scans(
        self, *, scanner: str, target: str, limit: int
    ) -> list[ScanHistoryEntry]:
        if limit < 1:
            raise ValueError("history limit must be at least 1")
        self.migrate()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM scans
                WHERE scanner = ? AND target = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (scanner, target, limit),
            ).fetchall()
        rows.reverse()
        return [self._entry(row) for row in rows]

    def get_scan(self, scan_id: int) -> ScanHistoryEntry | None:
        self.migrate()
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._entry(row) if row else None

    @staticmethod
    def _entry(row: sqlite3.Row) -> ScanHistoryEntry:
        return ScanHistoryEntry(**dict(row))
