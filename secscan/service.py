from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Callable, Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

JobStatus = Literal["queued", "running", "completed", "failed"]
ScanRunner = Callable[[list[str]], int]
ARTIFACT_PATHS = {
    "trivy.json": Path("trivy.json"),
    "secscan.json": Path("secscan.json"),
    "secscan.html": Path("secscan.html"),
    "secscan.cdx.json": Path("secscan.cdx.json"),
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


class JobManager:
    def __init__(self, root: Path, runner: ScanRunner, max_workers: int = 2) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.root = root.expanduser().resolve()
        self.runner = runner
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="secscan")
        self._jobs: dict[str, JobRecord] = {}
        self._lock = Lock()

    def submit(self, request: ScanSubmission) -> JobRecord:
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
            self._jobs[job_id] = record
        self.executor.submit(self._run, job_id, request)
        return record

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

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
        record = self._require(job_id)
        record.status = "running"
        record.started_at = _timestamp()
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

    def _require(self, job_id: str) -> JobRecord:
        record = self.get(job_id)
        if record is None:
            raise KeyError(job_id)
        return record


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def create_app(
    *,
    job_root: Path = Path("/reports/jobs"),
    max_workers: int = 2,
    runner: ScanRunner | None = None,
) -> FastAPI:
    if runner is None:
        from secscan.cli import main

        runner = main
    manager = JobManager(job_root, runner, max_workers=max_workers)
    app = FastAPI(title="secscan API", version="1.0.0")

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/jobs", status_code=202)
    def submit_job(request: ScanSubmission) -> dict[str, object]:
        return asdict(manager.submit(request))

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, object]:
        record = manager.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return asdict(record)

    @app.get("/api/v1/jobs/{job_id}/artifacts/{name}")
    def get_artifact(job_id: str, name: str) -> FileResponse:
        record = manager.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        artifact = manager.artifact_path(record, name)
        if artifact is None or not artifact.is_file():
            raise HTTPException(status_code=404, detail="artifact not found")
        return FileResponse(artifact)

    return app


app = create_app()
