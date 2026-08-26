from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Literal, cast

from fastapi import FastAPI, HTTPException, Response
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secscan.scanners.linux_host import validate_ssh_user
from secscan.scanners.network import validate_network_target
from secscan.service import ScanSubmission, create_app

_WEB_ROOT = Path(__file__).with_name("web_assets")
_TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class LinuxHostWebSubmission(BaseModel):
    target: str = Field(min_length=1)
    fail_on: Literal["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    policy: str | None = None
    baseline: str | None = None
    timeout: int = Field(default=600, ge=1, le=86400)
    linux_host_authorized: bool = False


def _linux_host_service_ready() -> bool:
    user = os.environ.get("SECSCAN_SSH_USER", "")
    key = os.environ.get("SECSCAN_SSH_KEY", "")
    known_hosts = os.environ.get("SECSCAN_SSH_KNOWN_HOSTS", "")
    port = os.environ.get("SECSCAN_SSH_PORT", "22")
    try:
        validate_ssh_user(user)
        parsed_port = int(port)
    except (ValueError, TypeError):
        return False
    if not 1 <= parsed_port <= 65535:
        return False
    for value in (key, known_hosts):
        path = Path(value).expanduser()
        if not path.is_absolute() or not path.is_file():
            return False
    return True


def _job_submitter(app: FastAPI) -> Callable[[ScanSubmission], dict[str, object]]:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == "/api/v1/jobs"
            and route.methods is not None
            and "POST" in route.methods
        ):
            return cast(Callable[[ScanSubmission], dict[str, object]], route.endpoint)
    raise RuntimeError("secscan job submission route is unavailable")


def mount_web_ui(
    app: FastAPI,
    *,
    job_root: Path = Path("/reports/jobs"),
    job_database: Path | None = None,
) -> FastAPI:
    """Mount the browser UI and web-only helpers onto a secscan FastAPI app."""
    resolved_root = job_root.expanduser().resolve()
    database = (job_database or resolved_root / "jobs.db").expanduser().resolve()
    submit_job = _job_submitter(app)

    def job_storage(job_id: str) -> tuple[str, Path]:
        if not database.is_file():
            raise HTTPException(status_code=404, detail="job not found")
        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT status, output_dir FROM service_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="job not found")
        status, output_dir = str(row[0]), str(row[1])
        job_dir = (resolved_root / job_id).resolve()
        recorded_dir = Path(output_dir).resolve()
        if job_dir != recorded_dir or not job_dir.is_relative_to(resolved_root):
            raise HTTPException(status_code=409, detail="job output directory is not safe")
        return status, job_dir

    @app.get("/api/v1/linux-host-capability")
    def linux_host_capability() -> dict[str, bool]:
        return {"configured": _linux_host_service_ready()}

    @app.post("/api/v1/linux-host-jobs", status_code=202)
    def submit_linux_host_job(request: LinuxHostWebSubmission) -> dict[str, object]:
        if not request.linux_host_authorized:
            raise HTTPException(
                status_code=422,
                detail="Linux host scans require explicit authorization acknowledgement",
            )
        try:
            validate_network_target(request.target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not _linux_host_service_ready():
            raise HTTPException(
                status_code=422,
                detail=(
                    "Linux host scanning is not configured on this service. Configure the "
                    "server-side SECSCAN_SSH_* settings and read-only SSH credential mount."
                ),
            )
        submission = ScanSubmission.model_construct(
            scanner="linux-host",
            target=request.target,
            fail_on=request.fail_on,
            policy=request.policy,
            baseline=request.baseline,
            timeout=request.timeout,
            network_authorized=False,
        )
        return submit_job(submission)

    @app.get("/api/v1/jobs/{job_id}/summary")
    def job_summary(job_id: str) -> dict[str, object]:
        status, job_dir = job_storage(job_id)
        report_path = job_dir / "secscan.json"
        if not report_path.is_file():
            raise HTTPException(status_code=404, detail="scan report not found")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail="scan report is not valid JSON") from exc
        findings = report.get("findings", []) if isinstance(report, dict) else []
        counts = {severity: 0 for severity in _SEVERITIES}
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity", "UNKNOWN")).upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1
        return {
            "job_id": job_id,
            "status": status,
            "total": sum(counts.values()),
            "severity": counts,
        }

    @app.delete("/api/v1/jobs/{job_id}/history", status_code=204)
    def delete_job_history(job_id: str) -> Response:
        status, job_dir = job_storage(job_id)
        if status not in _TERMINAL_JOB_STATUSES:
            raise HTTPException(status_code=409, detail="active jobs cannot be deleted")
        if job_dir.exists():
            shutil.rmtree(job_dir)
        with sqlite3.connect(database) as connection:
            connection.execute("DELETE FROM service_jobs WHERE id = ?", (job_id,))
        return Response(status_code=204)

    app.mount("/", StaticFiles(directory=_WEB_ROOT, html=True), name="web")
    return app


def create_web_app(**service_options: Any) -> FastAPI:
    """Create the secscan API and mount the browser UI at the site root."""
    job_root = Path(service_options.get("job_root", Path("/reports/jobs")))
    job_database = service_options.get("job_database")
    return mount_web_ui(
        create_app(**service_options),
        job_root=job_root,
        job_database=job_database,
    )
