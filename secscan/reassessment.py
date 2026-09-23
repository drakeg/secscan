from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from uuid import uuid4


CADENCE_INTERVALS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}


@dataclass(frozen=True)
class ReassessmentSchedule:
    id: str
    tenant_id: str
    asset_id: str
    project_id: str | None
    cadence: str
    enabled: bool
    next_run_at: str
    last_attempted_at: str | None
    last_enqueued_at: str | None
    created_by: str
    created_at: str
    updated_at: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "project_id": self.project_id,
            "cadence": self.cadence,
            "enabled": self.enabled,
            "next_run_at": self.next_run_at,
            "last_attempted_at": self.last_attempted_at,
            "last_enqueued_at": self.last_enqueued_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("schedule time must be timezone-aware")
    return value.astimezone(UTC)


def next_run_for(cadence: str, *, now: datetime) -> datetime:
    try:
        interval = CADENCE_INTERVALS[cadence]
    except KeyError as exc:
        raise ValueError("cadence must be daily or weekly") from exc
    return _utc(now) + interval


class ReassessmentScheduleStore:
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
                CREATE TABLE IF NOT EXISTS reassessment_schedules (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    project_id TEXT,
                    cadence TEXT NOT NULL CHECK(cadence IN ('daily', 'weekly')),
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    next_run_at TEXT NOT NULL,
                    last_attempted_at TEXT,
                    last_enqueued_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tenant_id, asset_id, project_id)
                );
                CREATE INDEX IF NOT EXISTS reassessment_schedules_due_idx
                    ON reassessment_schedules(enabled, next_run_at);
                CREATE INDEX IF NOT EXISTS reassessment_schedules_tenant_idx
                    ON reassessment_schedules(tenant_id, created_at, id);
                """
            )

    def create(
        self,
        *,
        tenant_id: str,
        asset_id: str,
        created_by: str,
        cadence: str,
        project_id: str | None = None,
        now: datetime | None = None,
    ) -> ReassessmentSchedule:
        if not tenant_id.strip() or not asset_id.strip() or not created_by.strip():
            raise ValueError("tenant, asset, and creator are required")
        current = _utc(now or datetime.now(UTC))
        next_run = next_run_for(cadence, now=current)
        timestamp = current.isoformat()
        schedule_id = str(uuid4())
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO reassessment_schedules (
                        id, tenant_id, asset_id, project_id, cadence, enabled,
                        next_run_at, created_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        schedule_id,
                        tenant_id,
                        asset_id,
                        project_id,
                        cadence,
                        next_run.isoformat(),
                        created_by,
                        timestamp,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("a reassessment schedule already exists for this asset scope") from exc
        return self.get(schedule_id, tenant_id=tenant_id)

    def get(self, schedule_id: str, *, tenant_id: str) -> ReassessmentSchedule:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reassessment_schedules WHERE id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            ).fetchone()
        if row is None:
            raise ValueError("reassessment schedule was not found")
        return _schedule(row)

    def list(self, *, tenant_id: str) -> list[ReassessmentSchedule]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM reassessment_schedules
                WHERE tenant_id = ?
                ORDER BY created_at, id
                """,
                (tenant_id,),
            ).fetchall()
        return [_schedule(row) for row in rows]

    def due(self, *, now: datetime, limit: int = 100) -> list[ReassessmentSchedule]:
        if limit < 1 or limit > 100:
            raise ValueError("due schedule limit must be between 1 and 100")
        current = _utc(now)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM reassessment_schedules
                WHERE enabled = 1 AND next_run_at <= ?
                ORDER BY next_run_at, id
                LIMIT ?
                """,
                (current.isoformat(), limit),
            ).fetchall()
        return [_schedule(row) for row in rows]

    def record_attempt(
        self,
        schedule_id: str,
        *,
        tenant_id: str,
        enqueued: bool,
        now: datetime,
    ) -> ReassessmentSchedule:
        current = _utc(now)
        schedule = self.get(schedule_id, tenant_id=tenant_id)
        next_run = next_run_for(schedule.cadence, now=current)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE reassessment_schedules
                SET next_run_at = ?,
                    last_attempted_at = ?,
                    last_enqueued_at = CASE WHEN ? THEN ? ELSE last_enqueued_at END,
                    updated_at = ?
                WHERE id = ? AND tenant_id = ?
                """,
                (
                    next_run.isoformat(),
                    current.isoformat(),
                    int(enqueued),
                    current.isoformat(),
                    current.isoformat(),
                    schedule_id,
                    tenant_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("reassessment schedule was not found")
        return self.get(schedule_id, tenant_id=tenant_id)


def _schedule(row: sqlite3.Row) -> ReassessmentSchedule:
    return ReassessmentSchedule(
        id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        asset_id=str(row["asset_id"]),
        project_id=str(row["project_id"]) if row["project_id"] is not None else None,
        cadence=str(row["cadence"]),
        enabled=bool(row["enabled"]),
        next_run_at=str(row["next_run_at"]),
        last_attempted_at=(
            str(row["last_attempted_at"]) if row["last_attempted_at"] is not None else None
        ),
        last_enqueued_at=(
            str(row["last_enqueued_at"]) if row["last_enqueued_at"] is not None else None
        ),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
