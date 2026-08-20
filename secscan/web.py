from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles

from secscan.service import create_app

_WEB_ROOT = Path(__file__).with_name("web_assets")
_TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def mount_web_ui(
    app: FastAPI,
    *,
    job_root: Path = Path("/reports/jobs"),
    job_database: Path | None = None,
) -> FastAPI:
    """Mount the browser UI and web-only helpers onto a secscan FastAPI app."""
    resolved_root = job_root.expanduser().resolve()
    database = (job_database or resolved_root / "jobs.db").expanduser().resolve()

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
