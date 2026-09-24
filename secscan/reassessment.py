from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import sqlite3
from threading import Event, Thread
from collections.abc import Callable
from typing import List, Literal, cast
from uuid import uuid4

from secscan.assets import AssetRecord, AssetStore
from secscan.auth import AuthStore, User
from secscan.project_access import ProjectAccessStore
from secscan.project_jobs import ProjectJobStore
from secscan.service import JobManager, JobRecord, JobStore, ScanSubmission
from secscan.scanners.repository import is_remote_repository_url, validate_remote_repository_url
from secscan.scanners.repository import is_remote_repository_url, validate_remote_repository_url


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
    claim_token: str | None
    claim_expires_at: str | None
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


type ReassessmentScanner = Literal["image", "repository"]
SAFE_REASSESSMENT_SCANNERS = {"image", "repository"}


class ReassessmentAssetAdapter:
    def __init__(self, database: Path) -> None:
        self.assets = AssetStore(database)
        self.jobs = JobStore(database)
        self.project_jobs = ProjectJobStore(database)

    def submission_for(self, schedule: ReassessmentSchedule) -> ScanSubmission:
        asset = self.assets.get(schedule.asset_id, tenant_id=schedule.tenant_id)
        if asset is None:
            raise ValueError("scheduled asset is unavailable")
        self._validate_project_binding(schedule, asset)
        if asset.scanner not in SAFE_REASSESSMENT_SCANNERS:
            raise ValueError("asset scanner is not supported for reassessment")
        if asset.scanner == "repository":
            if not is_remote_repository_url(asset.target):
                raise ValueError(
                    "repository reassessment requires a remote repository URL"
                )
            validate_remote_repository_url(asset.target)
        latest = self.jobs.get(asset.latest_job_id, tenant_id=schedule.tenant_id)
        if latest is None or latest.scanner != asset.scanner or latest.target != asset.target:
            raise ValueError("scheduled asset job history is unavailable")
        scanner = cast(ReassessmentScanner, asset.scanner)
        return ScanSubmission(scanner=scanner, target=asset.target)

    def _validate_project_binding(
        self,
        schedule: ReassessmentSchedule,
        asset: AssetRecord,
    ) -> None:
        latest_project = self.project_jobs.project_id(
            asset.latest_job_id,
            tenant_id=schedule.tenant_id,
        )
        if schedule.project_id != latest_project:
            raise ValueError("scheduled asset project binding does not match job history")


class ReassessmentExecutor:
    def __init__(self, database: Path, manager: JobManager) -> None:
        self.schedules = ReassessmentScheduleStore(database)
        self.assets = ReassessmentAssetAdapter(database)
        self.project_jobs = ProjectJobStore(database)
        self.manager = manager

    def run_one(self, *, now: datetime) -> JobRecord | None:
        schedule = self.schedules.claim_due(now=now)
        if schedule is None:
            return None
        token = schedule.claim_token
        if token is None:
            raise RuntimeError("claimed reassessment schedule is missing its claim token")
        try:
            submission = self.assets.submission_for(schedule)
            job = self.manager.submit(submission, tenant_id=schedule.tenant_id)
            if schedule.project_id is not None:
                self.project_jobs.associate(
                    job_id=job.id,
                    tenant_id=schedule.tenant_id,
                    project_id=schedule.project_id,
                )
        except (OSError, RuntimeError, ValueError):
            self.schedules.record_attempt(
                schedule.id,
                tenant_id=schedule.tenant_id,
                enqueued=False,
                now=now,
                claim_token=token,
            )
            return None
        self.schedules.record_attempt(
            schedule.id,
            tenant_id=schedule.tenant_id,
            enqueued=True,
            now=now,
            claim_token=token,
        )
        return job


class ReassessmentScheduler:
    def __init__(
        self,
        executor: ReassessmentExecutor,
        *,
        interval: timedelta = timedelta(minutes=1),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if interval < timedelta(seconds=10) or interval > timedelta(hours=1):
            raise ValueError("scheduler interval must be between 10 seconds and 1 hour")
        self.executor = executor
        self.interval = interval
        self.clock = clock
        self._stop = Event()
        self._thread: Thread | None = None

    def tick(self, *, limit: int = 10) -> int:
        if limit < 1 or limit > 100:
            raise ValueError("scheduler tick limit must be between 1 and 100")
        processed = 0
        for _ in range(limit):
            if self.executor.run_one(now=_utc(self.clock())) is None:
                break
            processed += 1
        return processed

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="secscan-reassessment", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(self.interval.total_seconds() + 1, 5))
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(self.interval.total_seconds())


class ReassessmentScheduleCreate(BaseModel):
    asset_id: str
    project_id: str | None = None
    cadence: Literal["daily", "weekly"]


def mount_reassessment_schedules(app: FastAPI, *, database: Path) -> FastAPI:
    store = ReassessmentScheduleStore(database)
    authorizer = ReassessmentScheduleAuthorizer(database)

    def actor(request: Request) -> User:
        user = getattr(request.state, "secscan_user", None)
        if not isinstance(user, User):
            raise HTTPException(status_code=401, detail="authenticated tenant user is required")
        return user

    @app.get("/api/v1/reassessment-schedules")
    def list_schedules(request: Request) -> list[dict[str, object]]:
        user = actor(request)
        visible: list[dict[str, object]] = []
        for schedule in store.list(tenant_id=user.tenant_id):
            try:
                authorizer.require_schedule_access(user, schedule)
            except PermissionError:
                continue
            visible.append(schedule.public())
        return visible

    @app.post("/api/v1/reassessment-schedules", status_code=201)
    def create_schedule(
        request: Request,
        submission: ReassessmentScheduleCreate,
    ) -> dict[str, object]:
        user = actor(request)
        try:
            authorizer.require_manage(user, project_id=submission.project_id)
            schedule = store.create(
                tenant_id=user.tenant_id,
                asset_id=submission.asset_id,
                project_id=submission.project_id,
                cadence=submission.cadence,
                created_by=user.id,
            )
            ReassessmentAssetAdapter(database).submission_for(schedule)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return schedule.public()

    def mutable_schedule(request: Request, schedule_id: str) -> tuple[User, ReassessmentSchedule]:
        user = actor(request)
        try:
            schedule = store.get(schedule_id, tenant_id=user.tenant_id)
            authorizer.require_schedule_access(user, schedule)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return user, schedule

    @app.post("/api/v1/reassessment-schedules/{schedule_id}/pause")
    def pause_schedule(schedule_id: str, request: Request) -> dict[str, object]:
        user, _schedule = mutable_schedule(request, schedule_id)
        return store.set_enabled(schedule_id, tenant_id=user.tenant_id, enabled=False).public()

    @app.post("/api/v1/reassessment-schedules/{schedule_id}/resume")
    def resume_schedule(schedule_id: str, request: Request) -> dict[str, object]:
        user, _schedule = mutable_schedule(request, schedule_id)
        return store.set_enabled(schedule_id, tenant_id=user.tenant_id, enabled=True).public()

    @app.delete("/api/v1/reassessment-schedules/{schedule_id}", status_code=204)
    def delete_schedule(schedule_id: str, request: Request) -> None:
        user, _schedule = mutable_schedule(request, schedule_id)
        store.delete(schedule_id, tenant_id=user.tenant_id)

    return app


class ReassessmentScheduleAuthorizer:
    def __init__(self, database: Path) -> None:
        self.auth = AuthStore(database)
        self.projects = ProjectAccessStore(database)

    def require_manage(self, actor: User, *, project_id: str | None) -> None:
        tenant_role = self.auth.membership_role(actor.id, actor.tenant_id)
        if tenant_role == "owner":
            if project_id is not None:
                self.projects.require_operator(actor, project_id)
            return
        if project_id is None:
            raise PermissionError("tenant owner access required")
        try:
            self.projects.require_operator(actor, project_id)
        except ValueError as exc:
            raise PermissionError("project operator access required") from exc

    def require_schedule_access(
        self,
        actor: User,
        schedule: ReassessmentSchedule,
    ) -> None:
        if schedule.tenant_id != actor.tenant_id:
            raise ValueError("reassessment schedule was not found")
        self.require_manage(actor, project_id=schedule.project_id)


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
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tenant_id, asset_id, project_id)
                );
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(reassessment_schedules)"
                ).fetchall()
            }
            if "claim_token" not in columns:
                connection.execute(
                    "ALTER TABLE reassessment_schedules ADD COLUMN claim_token TEXT"
                )
            if "claim_expires_at" not in columns:
                connection.execute(
                    "ALTER TABLE reassessment_schedules ADD COLUMN claim_expires_at TEXT"
                )
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS reassessment_schedules_due_idx
                    ON reassessment_schedules(enabled, next_run_at);
                CREATE INDEX IF NOT EXISTS reassessment_schedules_tenant_idx
                    ON reassessment_schedules(tenant_id, created_at, id);
                CREATE UNIQUE INDEX IF NOT EXISTS reassessment_schedules_tenant_asset_unique_idx
                    ON reassessment_schedules(tenant_id, asset_id)
                    WHERE project_id IS NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS reassessment_schedules_project_asset_unique_idx
                    ON reassessment_schedules(tenant_id, asset_id, project_id)
                    WHERE project_id IS NOT NULL;
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

    def list(self, *, tenant_id: str) -> List[ReassessmentSchedule]:
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

    def set_enabled(
        self,
        schedule_id: str,
        *,
        tenant_id: str,
        enabled: bool,
        now: datetime | None = None,
    ) -> ReassessmentSchedule:
        current = _utc(now or datetime.now(UTC))
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE reassessment_schedules
                SET enabled = ?, updated_at = ?,
                    claim_token = CASE WHEN ? THEN claim_token ELSE NULL END,
                    claim_expires_at = CASE WHEN ? THEN claim_expires_at ELSE NULL END
                WHERE id = ? AND tenant_id = ?
                """,
                (
                    int(enabled),
                    current.isoformat(),
                    int(enabled),
                    int(enabled),
                    schedule_id,
                    tenant_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("reassessment schedule was not found")
        return self.get(schedule_id, tenant_id=tenant_id)

    def delete(self, schedule_id: str, *, tenant_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM reassessment_schedules WHERE id = ? AND tenant_id = ?",
                (schedule_id, tenant_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("reassessment schedule was not found")

    def due(self, *, now: datetime, limit: int = 100) -> List[ReassessmentSchedule]:
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

    def claim_due(
        self,
        *,
        now: datetime,
        lease: timedelta = timedelta(minutes=5),
    ) -> ReassessmentSchedule | None:
        current = _utc(now)
        if lease <= timedelta(0) or lease > timedelta(minutes=30):
            raise ValueError("claim lease must be positive and at most 30 minutes")
        token = str(uuid4())
        expires = current + lease
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT id, tenant_id FROM reassessment_schedules
                WHERE enabled = 1
                  AND next_run_at <= ?
                  AND (claim_expires_at IS NULL OR claim_expires_at <= ?)
                ORDER BY next_run_at, id
                LIMIT 1
                """,
                (current.isoformat(), current.isoformat()),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE reassessment_schedules
                SET claim_token = ?, claim_expires_at = ?, updated_at = ?
                WHERE id = ? AND tenant_id = ?
                """,
                (
                    token,
                    expires.isoformat(),
                    current.isoformat(),
                    row["id"],
                    row["tenant_id"],
                ),
            )
        return self.get(str(row["id"]), tenant_id=str(row["tenant_id"]))

    def release_claim(
        self,
        schedule_id: str,
        *,
        tenant_id: str,
        claim_token: str,
        now: datetime,
    ) -> None:
        current = _utc(now)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE reassessment_schedules
                SET claim_token = NULL, claim_expires_at = NULL, updated_at = ?
                WHERE id = ? AND tenant_id = ? AND claim_token = ?
                """,
                (current.isoformat(), schedule_id, tenant_id, claim_token),
            )
            if cursor.rowcount != 1:
                raise ValueError("reassessment schedule claim was not found")

    def record_attempt(
        self,
        schedule_id: str,
        *,
        tenant_id: str,
        enqueued: bool,
        now: datetime,
        claim_token: str | None = None,
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
                    updated_at = ?,
                    claim_token = NULL,
                    claim_expires_at = NULL
                WHERE id = ? AND tenant_id = ?
                  AND (
                      (claim_token IS NULL AND ? IS NULL)
                      OR claim_token = ?
                  )
                """,
                (
                    next_run.isoformat(),
                    current.isoformat(),
                    int(enqueued),
                    current.isoformat(),
                    current.isoformat(),
                    schedule_id,
                    tenant_id,
                    claim_token,
                    claim_token,
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
        claim_token=str(row["claim_token"]) if row["claim_token"] is not None else None,
        claim_expires_at=(
            str(row["claim_expires_at"]) if row["claim_expires_at"] is not None else None
        ),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )
