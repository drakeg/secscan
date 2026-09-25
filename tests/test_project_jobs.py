from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, cast

from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
import pytest

from secscan.auth import AuthStore, User
from secscan.project_jobs import ProjectJobStore, ProjectScanSubmission, mount_project_job_association
from secscan.projects import ProjectStore
from secscan.service import create_app


def _route(app: FastAPI, path: str, method: str) -> Callable[..., Any]:
    for route in app.routes:
        if (
            isinstance(route, APIRoute)
            and route.path == path
            and route.methods is not None
            and method in route.methods
        ):
            return cast(Callable[..., Any], route.endpoint)
    raise AssertionError(f"missing {method} {path}")


def _request(user: User) -> Request:
    return Request({"type": "http", "state": {"secscan_user": user}})


def _app(tmp_path: Path) -> tuple[FastAPI, Path, AuthStore, ProjectStore]:
    root = tmp_path / "jobs"
    database = root / "jobs.db"
    app = create_app(job_root=root, job_database=database, runner=lambda _args: 0)
    auth = AuthStore(database)
    projects = ProjectStore(database)
    mount_project_job_association(app, database=database)
    return app, database, auth, projects


def test_project_job_association_is_persisted_and_exposed(tmp_path: Path) -> None:
    app, _database, auth, projects = _app(tmp_path)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")
    request = _request(owner)

    submit = _route(app, "/api/v1/jobs", "POST")
    get_job = _route(app, "/api/v1/jobs/{job_id}", "GET")
    list_jobs = _route(app, "/api/v1/jobs", "GET")

    submitted = submit(
        request,
        ProjectScanSubmission(scanner="image", target="alpine:3.20", project_id=project.id),
    )
    assert submitted["project_id"] == project.id
    job_id = str(submitted["id"])

    detail = get_job(job_id, request)
    assert detail["project_id"] == project.id

    listed = list_jobs(request=request, status=None, scanner=None, limit=20)
    assert any(job["id"] == job_id and job["project_id"] == project.id for job in listed)


def test_unprojected_jobs_remain_supported(tmp_path: Path) -> None:
    app, _database, auth, _projects = _app(tmp_path)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    request = _request(owner)
    submit = _route(app, "/api/v1/jobs", "POST")
    get_job = _route(app, "/api/v1/jobs/{job_id}", "GET")

    submitted = submit(request, ProjectScanSubmission(scanner="image", target="alpine:3.20"))
    assert "project_id" not in submitted
    detail = get_job(str(submitted["id"]), request)
    assert detail["project_id"] is None


def test_disabled_project_rejects_new_job_but_historical_link_remains(tmp_path: Path) -> None:
    app, _database, auth, projects = _app(tmp_path)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")
    request = _request(owner)
    submit = _route(app, "/api/v1/jobs", "POST")
    get_job = _route(app, "/api/v1/jobs/{job_id}", "GET")

    submitted = submit(
        request,
        ProjectScanSubmission(scanner="image", target="alpine:3.20", project_id=project.id),
    )
    job_id = str(submitted["id"])
    projects.update(owner, project.id, enabled=False)

    assert get_job(job_id, request)["project_id"] == project.id
    with pytest.raises(HTTPException) as exc_info:
        submit(
            request,
            ProjectScanSubmission(scanner="image", target="busybox:latest", project_id=project.id),
        )
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "project is disabled"


def test_cross_tenant_project_id_fails_closed(tmp_path: Path) -> None:
    app, _database, auth, projects = _app(tmp_path)
    first = auth.register("first@example.com", "correct-horse-battery-staple")
    second = auth.register("second@example.com", "correct-horse-battery-staple")
    second_project = projects.create(second, "Second tenant project")
    submit = _route(app, "/api/v1/jobs", "POST")

    with pytest.raises(HTTPException) as exc_info:
        submit(
            _request(first),
            ProjectScanSubmission(
                scanner="image",
                target="alpine:3.20",
                project_id=second_project.id,
            ),
        )
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "project was not found"


def test_project_association_exists_before_worker_starts(tmp_path: Path) -> None:
    from threading import Event

    root = tmp_path / "jobs"
    database = root / "jobs.db"
    worker_started = Event()
    association_seen = Event()

    def runner(_args: list[str]) -> int:
        worker_started.set()
        return 0

    app = create_app(job_root=root, job_database=database, runner=runner)
    auth = AuthStore(database)
    projects = ProjectStore(database)
    mount_project_job_association(app, database=database)
    owner = auth.register("owner@example.com", "correct-horse-battery-staple")
    project = projects.create(owner, "Production")
    submit = _route(app, "/api/v1/jobs", "POST")

    submitted = submit(
        _request(owner),
        ProjectScanSubmission(scanner="image", target="alpine:3.20", project_id=project.id),
    )
    job_id = str(submitted["id"])
    if ProjectJobStore(database).project_id(job_id, tenant_id=owner.tenant_id) == project.id:
        association_seen.set()

    assert association_seen.is_set()
    assert submitted["project_id"] == project.id
