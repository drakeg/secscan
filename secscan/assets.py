from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import sqlite3


@dataclass(frozen=True)
class AssetRecord:
    id: str
    scanner: str
    target: str
    first_seen_at: str
    last_seen_at: str
    latest_job_id: str
    scan_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AssetStore:
    """Persistent scanner/target inventory derived from service job history."""

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
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS service_assets (
                    id TEXT PRIMARY KEY,
                    scanner TEXT NOT NULL,
                    target TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    latest_job_id TEXT NOT NULL,
                    scan_count INTEGER NOT NULL CHECK(scan_count >= 1),
                    UNIQUE(scanner, target)
                );
                CREATE INDEX IF NOT EXISTS service_assets_last_seen_idx
                    ON service_assets(last_seen_at DESC);
                """
            )

    @staticmethod
    def asset_id(scanner: str, target: str) -> str:
        identity = f"{scanner}\0{target}".encode("utf-8")
        return hashlib.sha256(identity).hexdigest()

    def reconcile_jobs(self) -> None:
        """Rebuild current asset facts from durable service job history."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scanner, target,
                       MIN(created_at) AS first_seen_at,
                       MAX(created_at) AS last_seen_at,
                       COUNT(*) AS scan_count
                FROM service_jobs
                GROUP BY scanner, target
                """
            ).fetchall()
            for row in rows:
                latest = connection.execute(
                    """
                    SELECT id FROM service_jobs
                    WHERE scanner = ? AND target = ?
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1
                    """,
                    (row["scanner"], row["target"]),
                ).fetchone()
                if latest is None:
                    continue
                asset_id = self.asset_id(str(row["scanner"]), str(row["target"]))
                connection.execute(
                    """
                    INSERT INTO service_assets (
                        id, scanner, target, first_seen_at, last_seen_at,
                        latest_job_id, scan_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scanner, target) DO UPDATE SET
                        first_seen_at = excluded.first_seen_at,
                        last_seen_at = excluded.last_seen_at,
                        latest_job_id = excluded.latest_job_id,
                        scan_count = excluded.scan_count
                    """,
                    (
                        asset_id,
                        row["scanner"],
                        row["target"],
                        row["first_seen_at"],
                        row["last_seen_at"],
                        latest["id"],
                        row["scan_count"],
                    ),
                )

    def list(self, *, limit: int = 100) -> list[AssetRecord]:
        self.reconcile_jobs()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM service_assets ORDER BY last_seen_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AssetRecord(**dict(row)) for row in rows]

    def get(self, asset_id: str) -> AssetRecord | None:
        self.reconcile_jobs()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM service_assets WHERE id = ?",
                (asset_id,),
            ).fetchone()
        return AssetRecord(**dict(row)) if row else None
