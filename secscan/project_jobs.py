from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import sqlite3
from typing import Any, cast

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.routing import APIRoute
from pydantic import Field

from secscan.auth import User
from secscan.project_access import ProjectAccessStore
from secscan.service import JobStatus, ScanSubmission, ScannerName
from secscan.tenancy import request_tenant_id


class ProjectScanSubmission(ScanSubmission):
    project_id: str | None = Field(default=None, min_length=1, max_length=128)


class ProjectJobStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS service_job_projects (
                    job_id TEXT PRIMARY KEY REFERENCES service_jobs(id) ON DELETE CASCADE,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL REFERENCES tenant_projects(id),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS service_job_projects_tenant_project_idx
                    ON service_job_projects(tenant_id, project_id);
                """
            )

    def associate(self, *, job_id: str, tenant_id: str, project_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO service_job_projects (job_id, tenant_id, project_id)
                   VALUES (?, ?, ?)""",
                (job_id, tenant_id, project_id),
            )

    def project_id(self, job_id: str, *, tenant_id: str | None) -> str | None:
        if tenant_id is None:
            return None
        with self._connect() as connection:
            row = connection.execute(
                """SELECT project_id FROM service_job_projects
                   WHERE job_id = ? AND tenant_id = ?""",
                (job_id, tenant_id),
            ).fetchone()
        return str(row["project_id"]) if row is not None else None

    def project_ids(self, job_ids: list[str], *, tenant_id: str | None) -> dict[str, str]:
        if tenant_id is None or not job_ids:
            return {}
        placeholders = ",".join("?" for _ in job_ids)
        with self._connect() as connection:
            rows = connection.execute(
                f"""SELECT job_id, project_id FROM service_job_projects
                    WHERE tenant_id = ? AND job_id IN ({placeholders})""",
                (tenant_id, *job_ids),
            ).fetchall()
        return {str(row["job_id"]): str(row["project_id"]) for row in rows}


def _current_user(request: Request) -> User:
    user = getattr(request.state, "secscan_user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="authenticated tenant user is required")
    return user


def _route(app: FastAPI, *, path: str, method: str) -> APIRoute:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == path
            and route.methods is not None
            and method in route.methods
        ):
            return route
    raise RuntimeError(f"secscan route {method} {path} is unavailable")


def mount_project_job_association(app: FastAPI, *, database: Path) -> FastAPI:
    access_store = ProjectAccessStore(database)
    link_store = ProjectJobStore(database)

    submit_route = _route(app, path="/api/v1/jobs", method="POST")
    list_route = _route(app, path="/api/v1/jobs", method="GET")
    get_route = _route(app, path="/api/v1/jobs/{job_id}", method="GET")

    submit_original = cast(Callable[[Request, ScanSubmission], dict[str, object]], submit_route.endpoint)
    get_manager = cast(Callable[[], object], app.state.secscan_get_manager)
    list_original = cast(Callable[..., list[dict[str, object]]], list_route.endpoint)
    get_original = cast(Callable[[str, Request], dict[str, object]], get_route.endpoint)

    app.router.routes.remove(submit_route)
    app.router.routes.remove(list_route)
    app.router.routes.remove(get_route)

    @app.post("/api/v1/jobs", status_code=202)
    def submit_job(request: Request, submission: ProjectScanSubmission) -> dict[str, object]:
        project_id = getattr(submission, "project_id", None)
        base_submission = ScanSubmission.model_validate(submission.model_dump(exclude={"project_id"}))
        if project_id is None:
            return submit_original(request, base_submission)

        user = _current_user(request)
        try:
            access_store.require_operator(user, project_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        manager = cast(Any, get_manager())
        try:
            record = manager.submit(
                base_submission,
                tenant_id=user.tenant_id,
                before_enqueue=lambda queued: link_store.associate(
                    job_id=queued.id,
                    tenant_id=user.tenant_id,
                    project_id=project_id,
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        document = {
            key: value
            for key, value in record.__dict__.items()
            if key != "tenant_id"
        }
        document["project_id"] = project_id
        return document

    @app.get("/api/v1/jobs")
    def list_jobs(
        request: Request,
        status: JobStatus | None = None,
        scanner: ScannerName | None = None,
        limit: int = Query(default=20, ge=1, le=100),
    ) -> list[dict[str, object]]:
        documents = list_original(request=request, status=status, scanner=scanner, limit=limit)
        user = getattr(request.state, "secscan_user", None)
        ids = [str(document["id"]) for document in documents if isinstance(document.get("id"), str)]
        links = link_store.project_ids(ids, tenant_id=request_tenant_id(request))
        visible: list[dict[str, object]] = []
        for document in documents:
            job_id = document.get("id")
            project_id = links.get(job_id) if isinstance(job_id, str) else None
            if project_id is not None and isinstance(user, User):
                try:
                    access_store.require_read(user, project_id)
                except (PermissionError, ValueError):
                    continue
            document["project_id"] = project_id
            visible.append(document)
        return visible

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict[str, object]:
        document = get_original(job_id, request)
        project_id = link_store.project_id(job_id, tenant_id=request_tenant_id(request))
        if project_id is not None:
            user = _current_user(request)
            try:
                access_store.require_read(user, project_id)
            except (PermissionError, ValueError) as exc:
                raise HTTPException(status_code=404, detail="job not found") from exc
        document["project_id"] = project_id
        return document

    return app
