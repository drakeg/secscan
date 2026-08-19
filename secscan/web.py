from __future__ import annotations

from pathlib import Path
import shutil
import sqlite3
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles

from secscan.service import create_app

_WEB_ROOT = Path(__file__).with_name("web_assets")
_TERMINAL_JOB_STATUSES = {"completed", "failed", "cancelled"}


def mount_web_ui(
    app: FastAPI,
    *,
    job_root: Path = Path("/reports/jobs"),
    job_database: Path | None = None,
) -> FastAPI:
    """Mount the browser UI and web-only helpers onto a secscan FastAPI app."""
    resolved_root = job_root.expanduser().resolve()
    database = (job_database or resolved_root / "jobs.db").expanduser().resolve()

    @app.delete("/api/v1/jobs/{job_id}/history", status_code=204)
    def delete_job_history(job_id: str) -> Response:
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
            if status not in _TERMINAL_JOB_STATUSES:
                raise HTTPException(status_code=409, detail="active jobs cannot be deleted")

            job_dir = (resolved_root / job_id).resolve()
            recorded_dir = Path(output_dir).resolve()
            if job_dir != recorded_dir or not job_dir.is_relative_to(resolved_root):
                raise HTTPException(status_code=409, detail="job output directory is not safe to delete")

            if job_dir.exists():
                shutil.rmtree(job_dir)
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
