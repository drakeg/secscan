from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import os
from pathlib import Path, PurePath
import sqlite3
from threading import Lock
from typing import Callable, Literal, Sequence
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

JobStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
ScanRunner = Callable[[list[str]], int]
ARTIFACT_PATHS = {
    "trivy.json": Path("trivy.json"),
    "secscan.json": Path("secscan.json"),
    "secscan.html": Path("secscan.html"),
    "secscan.cdx.json": Path("secscan.cdx.json"),
    "secscan.spdx.json": Path("secscan.spdx.json"),
    "secscan.diff.json": Path("secscan.diff.json"),
}


class ScanSubmission(BaseModel):
    scanner: Literal["image", "filesystem", "repository", "sbom"]
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)


@dataclass
class JobRecord:
    id: str
    status: JobStatus
    scanner: str
    target: str
    output_dir: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    exit_code: int | None = None
    error: str | None = None


class JobStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS service_jobs (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    target TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    exit_code INTEGER,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS service_jobs_created_at_idx
                    ON service_jobs(created_at DESC);
                CREATE INDEX IF NOT EXISTS service_jobs_status_created_at_idx
                    ON service_jobs(status, created_at DESC);
                """
            )

    def save(self, record: JobRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO service_jobs (
                    id, status, scanner, target, output_dir, created_at,
                    started_at, completed_at, exit_code, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    exit_code = excluded.exit_code,
                    error = excluded.error
                """,
                (
                    record.id,
                    record.status,
                    record.scanner,
                    record.target,
                    record.output_dir,
                    record.created_at,
                    record.started_at,
                    record.completed_at,
                    record.exit_code,
                    record.error,
                ),
            )

    def get(self, job_id: str) -> JobRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM service_jobs WHERE id = ?", (job_id,)).fetchone()
        return JobRecord(**dict(row)) if row else None

    def list(
        self,
        *,
        status: JobStatus | None = None,
        scanner: str | None = None,
        limit: int = 20,
    ) -> list[JobRecord]:
        with self._connect() as connection:
            if status is not None and scanner is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM service_jobs
                    WHERE status = ? AND scanner = ?
                    ORDER BY created_at DESC LIMIT ?
                    """,
                    (status, scanner, limit),
                ).fetchall()
            elif status is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM service_jobs
                    WHERE status = ? ORDER BY created_at DESC LIMIT ?
                    """,
                    (status, limit),
                ).fetchall()
            elif scanner is not None:
                rows = connection.execute(
                    """
                    SELECT * FROM service_jobs
                    WHERE scanner = ? ORDER BY created_at DESC LIMIT ?
                    """,
                    (scanner, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM service_jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [JobRecord(**dict(row)) for row in rows]

    def fail_interrupted(self) -> None:
        completed_at = _timestamp()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE service_jobs
                SET status = 'failed', completed_at = ?,
                    error = 'service restarted before the job completed'
                WHERE status IN ('queued', 'running')
                """,
                (completed_at,),
            )


class JobManager:
    def __init__(
        self,
        root: Path,
        runner: ScanRunner,
        max_workers: int = 2,
        database: Path | None = None,
        allowed_input_roots: Sequence[Path] = (),
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.root = root.expanduser().resolve()
        self.allowed_input_roots = tuple(path.expanduser().resolve() for path in allowed_input_roots)
        database_path = database or self.root / "jobs.db"
        self.store = JobStore(database_path.expanduser().resolve())
        self.store.fail_interrupted()
        self.runner = runner
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="secscan")
        self._lock = Lock()

    def submit(self, request: ScanSubmission) -> JobRecord:
        self._validate_input_paths(request)
        job_id = str(uuid4())
        output_dir = (self.root / job_id).resolve()
        if not output_dir.is_relative_to(self.root):
            raise ValueError("job output directory escaped the configured job root")
        record = JobRecord(
            id=job_id,
            status="queued",
            scanner=request.scanner,
            target=request.target,
            output_dir=str(output_dir),
            created_at=_timestamp(),
        )
        with self._lock:
            self.store.save(record)
        self.executor.submit(self._run, job_id, request)
        return record

    def _validate_input_paths(self, request: ScanSubmission) -> None:
        if not self.allowed_input_roots:
            return
        inputs: list[tuple[str, str]] = []
        if request.scanner in ("filesystem", "repository", "sbom"):
            inputs.append(("target", request.target))
        if request.policy is not None:
            inputs.append(("policy", request.policy))
        if request.baseline is not None:
            inputs.append(("baseline", request.baseline))
        for field, value in inputs:
            if not self._is_allowed_input_path(value):
                raise ValueError(f"{field} is outside the configured input roots")

    def _is_allowed_input_path(self, value: str) -> bool:
        lexical_path = PurePath(value)
        if not lexical_path.is_absolute():
            return False
        for root in self.allowed_input_roots:
            try:
                relative = lexical_path.relative_to(PurePath(root))
            except ValueError:
                continue
            safe_parts = tuple(os.path.basename(part) for part in relative.parts)
            if safe_parts != relative.parts or any(part in ("", ".", "..") for part in safe_parts):
                continue
            resolved = root.joinpath(*safe_parts).resolve()
            if resolved.is_relative_to(root):
                return True
        return False

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self.store.get(job_id)

    def list(
        self,
        *,
        status: JobStatus | None = None,
        scanner: str | None = None,
        limit: int = 20,
    ) -> list[JobRecord]:
        with self._lock:
            return self.store.list(status=status, scanner=scanner, limit=limit)

    def cancel(self, job_id: str) -> JobRecord | None:
        with self._lock:
            record = self.store.get(job_id)
            if record is None:
                return None
            if record.status != "queued":
                raise ValueError("only queued jobs can be cancelled")
            record.status = "cancelled"
            record.completed_at = _timestamp()
            self.store.save(record)
            return record

    def artifact_path(self, record: JobRecord, artifact_name: str) -> Path | None:
        relative_path = ARTIFACT_PATHS.get(artifact_name)
        if relative_path is None:
            return None
        job_dir = (self.root / record.id).resolve()
        recorded_dir = Path(record.output_dir).resolve()
        if job_dir != recorded_dir or not job_dir.is_relative_to(self.root):
            return None
        artifact = (job_dir / relative_path).resolve()
        if artifact.parent != job_dir or not artifact.is_relative_to(self.root):
            return None
        return artifact

    def _run(self, job_id: str, request: ScanSubmission) -> None:
        with self._lock:
            record = self.store.get(job_id)
            if record is None or record.status != "queued":
                return
            record.status = "running"
            record.started_at = _timestamp()
            self.store.save(record)
        args = [
            "scan",
            request.scanner,
            request.target,
            "--output-dir",
            record.output_dir,
            "--timeout",
            str(request.timeout),
        ]
        if request.fail_on:
            args.extend(["--fail-on", request.fail_on])
        if request.policy:
            args.extend(["--policy", request.policy])
        if request.baseline:
            args.extend(["--baseline", request.baseline])
        try:
            record.exit_code = self.runner(args)
            record.status = "completed" if record.exit_code in (0, 2) else "failed"
            if record.status == "failed":
                record.error = f"scan exited with code {record.exit_code}"
        except Exception as exc:  # defensive worker boundary
            record.status = "failed"
            record.error = str(exc)
        finally:
            record.completed_at = _timestamp()
            with self._lock:
                self.store.save(record)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def create_app(
    *,
    job_root: Path = Path("/reports/jobs"),
    max_workers: int = 2,
    job_database: Path | None = None,
    runner: ScanRunner | None = None,
    allowed_input_roots: Sequence[Path] = (),
) -> FastAPI:
    if runner is None:
        from secscan.cli import main

        runner = main
    manager: JobManager | None = None
    manager_lock = Lock()

    def get_manager() -> JobManager:
        nonlocal manager
        with manager_lock:
            if manager is None:
                manager = JobManager(
                    job_root,
                    runner,
                    max_workers=max_workers,
                    database=job_database,
                    allowed_input_roots=allowed_input_roots,
                )
            return manager

    app = FastAPI(title="secscan API", version="1.0.0")

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/jobs", status_code=202)
    def submit_job(request: ScanSubmission) -> dict[str, object]:
        try:
            record = get_manager().submit(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return asdict(record)

    @app.get("/api/v1/jobs")
    def list_jobs(
        status: JobStatus | None = None,
        scanner: Literal["image", "filesystem", "repository", "sbom"] | None = None,
        limit: int = Query(default=20, ge=1, le=100),
    ) -> list[dict[str, object]]:
        return [asdict(record) for record in get_manager().list(status=status, scanner=scanner, limit=limit)]

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, object]:
        record = get_manager().get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return asdict(record)

    @app.delete("/api/v1/jobs/{job_id}")
    def cancel_job(job_id: str) -> dict[str, object]:
        try:
            record = get_manager().cancel(job_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return asdict(record)

    @app.get("/api/v1/jobs/{job_id}/artifacts/{name}")
    def get_artifact(job_id: str, name: str) -> FileResponse:
        manager = get_manager()
        record = manager.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        artifact = manager.artifact_path(record, name)
        if artifact is None or not artifact.is_file():
            raise HTTPException(status_code=404, detail="artifact not found")
        return FileResponse(artifact)

    return app


app = create_app()
