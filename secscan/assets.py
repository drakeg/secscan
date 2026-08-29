from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import sqlite3

from secscan.tenancy import SYSTEM_TENANT_ID


@dataclass(frozen=True)
class AssetRecord:
    id: str
    tenant_id: str
    scanner: str
    target: str
    first_seen_at: str
    last_seen_at: str
    latest_job_id: str
    scan_count: int

    def to_dict(self) -> dict[str, object]:
        document = asdict(self)
        document.pop("tenant_id", None)
        return document


class AssetStore:
    """Persistent tenant-aware scanner/target inventory derived from service job history."""

    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            jobs_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_jobs'"
            ).fetchone()
            if jobs_table is not None:
                job_columns = {
                    str(row[1])
                    for row in connection.execute("PRAGMA table_info(service_jobs)").fetchall()
                }
                if "tenant_id" not in job_columns:
                    connection.execute(
                        f"ALTER TABLE service_jobs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '{SYSTEM_TENANT_ID}'"
                    )
                    auth_table = connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'auth_users'"
                    ).fetchone()
                    if auth_table is not None:
                        admin = connection.execute(
                            "SELECT id FROM auth_users WHERE role = 'admin' ORDER BY created_at ASC, id ASC LIMIT 1"
                        ).fetchone()
                        if admin is not None:
                            connection.execute(
                                "UPDATE service_jobs SET tenant_id = ? WHERE tenant_id = ?",
                                (str(admin["id"]), SYSTEM_TENANT_ID),
                            )

            asset_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(service_assets)").fetchall()
            }
            if asset_columns and "tenant_id" not in asset_columns:
                connection.execute("DROP TABLE service_assets")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS service_assets (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    target TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    latest_job_id TEXT NOT NULL,
                    scan_count INTEGER NOT NULL CHECK(scan_count >= 1),
                    UNIQUE(tenant_id, scanner, target)
                );
                CREATE INDEX IF NOT EXISTS service_assets_last_seen_idx
                    ON service_assets(last_seen_at DESC);
                CREATE INDEX IF NOT EXISTS service_assets_tenant_last_seen_idx
                    ON service_assets(tenant_id, last_seen_at DESC);
                """
            )

    @staticmethod
    def asset_id(scanner: str, target: str, tenant_id: str = SYSTEM_TENANT_ID) -> str:
        identity = f"{tenant_id}\0{scanner}\0{target}".encode("utf-8")
        return hashlib.sha256(identity).hexdigest()

    def reconcile_jobs(self) -> None:
        """Rebuild current asset facts from durable tenant-owned service job history."""
        with self._connect() as connection:
            jobs_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_jobs'"
            ).fetchone()
            if jobs_table is None:
                return
            rows = connection.execute(
                """
                SELECT tenant_id, scanner, target,
                       MIN(created_at) AS first_seen_at,
                       MAX(created_at) AS last_seen_at,
                       COUNT(*) AS scan_count
                FROM service_jobs
                GROUP BY tenant_id, scanner, target
                """
            ).fetchall()
            expected_ids: set[str] = set()
            for row in rows:
                latest = connection.execute(
                    """
                    SELECT id FROM service_jobs
                    WHERE tenant_id = ? AND scanner = ? AND target = ?
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1
                    """,
                    (row["tenant_id"], row["scanner"], row["target"]),
                ).fetchone()
                if latest is None:
                    continue
                tenant_id = str(row["tenant_id"])
                asset_id = self.asset_id(str(row["scanner"]), str(row["target"]), tenant_id)
                expected_ids.add(asset_id)
                connection.execute(
                    """
                    INSERT INTO service_assets (
                        id, tenant_id, scanner, target, first_seen_at, last_seen_at,
                        latest_job_id, scan_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, scanner, target) DO UPDATE SET
                        id = excluded.id,
                        first_seen_at = excluded.first_seen_at,
                        last_seen_at = excluded.last_seen_at,
                        latest_job_id = excluded.latest_job_id,
                        scan_count = excluded.scan_count
                    """,
                    (
                        asset_id,
                        tenant_id,
                        row["scanner"],
                        row["target"],
                        row["first_seen_at"],
                        row["last_seen_at"],
                        latest["id"],
                        row["scan_count"],
                    ),
                )
            if expected_ids:
                placeholders = ",".join("?" for _ in expected_ids)
                connection.execute(
                    f"DELETE FROM service_assets WHERE id NOT IN ({placeholders})",
                    tuple(sorted(expected_ids)),
                )
            else:
                connection.execute("DELETE FROM service_assets")

    def list(self, *, limit: int = 100, tenant_id: str | None = None) -> list[AssetRecord]:
        self.reconcile_jobs()
        with self._connect() as connection:
            if tenant_id is None:
                rows = connection.execute(
                    "SELECT * FROM service_assets ORDER BY last_seen_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM service_assets WHERE tenant_id = ? ORDER BY last_seen_at DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
        return [AssetRecord(**dict(row)) for row in rows]

    def get(self, asset_id: str, *, tenant_id: str | None = None) -> AssetRecord | None:
        self.reconcile_jobs()
        with self._connect() as connection:
            if tenant_id is None:
                row = connection.execute(
                    "SELECT * FROM service_assets WHERE id = ?",
                    (asset_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM service_assets WHERE id = ? AND tenant_id = ?",
                    (asset_id, tenant_id),
                ).fetchone()
        return AssetRecord(**dict(row)) if row else None
