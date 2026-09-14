from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from secscan.auth import AuthStore, User


@dataclass(frozen=True)
class Project:
    id: str
    tenant_id: str
    name: str
    enabled: bool
    created_by: str
    created_at: str
    updated_at: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ProjectCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class ProjectUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None


class ProjectStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.auth = AuthStore(self.path)
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
                CREATE TABLE IF NOT EXISTS tenant_projects (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                    created_by TEXT NOT NULL REFERENCES auth_users(id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tenant_id, name)
                );
                CREATE INDEX IF NOT EXISTS tenant_projects_tenant_enabled_name_idx
                    ON tenant_projects(tenant_id, enabled, name);
                """
            )

    @staticmethod
    def _name(value: str) -> str:
        name = " ".join(value.strip().split())
        if not name:
            raise ValueError("project name is required")
        if len(name) > 120:
            raise ValueError("project name must be 120 characters or fewer")
        return name

    def _require_member(self, actor: User) -> None:
        if self.auth.membership_role(actor.id, actor.tenant_id) is None:
            raise PermissionError("tenant membership is required")

    def _require_owner(self, actor: User) -> None:
        if self.auth.membership_role(actor.id, actor.tenant_id) != "owner":
            raise PermissionError("tenant owner access required")

    def create(self, actor: User, name: str) -> Project:
        self._require_owner(actor)
        now = datetime.now(UTC).isoformat()
        project = Project(str(uuid4()), actor.tenant_id, self._name(name), True, actor.id, now, now)
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO tenant_projects
                       (id, tenant_id, name, enabled, created_by, created_at, updated_at)
                       VALUES (?, ?, ?, 1, ?, ?, ?)""",
                    (project.id, project.tenant_id, project.name, project.created_by, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("a project with that name already exists in this tenant") from exc
        return project

    def list(self, actor: User) -> list[Project]:
        self._require_member(actor)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tenant_projects WHERE tenant_id = ? ORDER BY name, id",
                (actor.tenant_id,),
            ).fetchall()
        return [_project(row) for row in rows]

    def get(self, actor: User, project_id: str, *, require_enabled: bool = False) -> Project:
        self._require_member(actor)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM tenant_projects WHERE id = ? AND tenant_id = ?",
                (project_id, actor.tenant_id),
            ).fetchone()
        if row is None:
            raise ValueError("project was not found")
        project = _project(row)
        if require_enabled and not project.enabled:
            raise ValueError("project is disabled")
        return project

    def update(
        self,
        actor: User,
        project_id: str,
        *,
        name: str | None = None,
        enabled: bool | None = None,
    ) -> Project:
        self._require_owner(actor)
        current = self.get(actor, project_id)
        new_name = current.name if name is None else self._name(name)
        new_enabled = current.enabled if enabled is None else enabled
        now = datetime.now(UTC).isoformat()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """UPDATE tenant_projects SET name = ?, enabled = ?, updated_at = ?
                       WHERE id = ? AND tenant_id = ?""",
                    (new_name, int(new_enabled), now, project_id, actor.tenant_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError("project was not found")
        except sqlite3.IntegrityError as exc:
            raise ValueError("a project with that name already exists in this tenant") from exc
        return self.get(actor, project_id)


def _project(row: sqlite3.Row) -> Project:
    return Project(
        id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        name=str(row["name"]),
        enabled=bool(row["enabled"]),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _current_user(request: Request) -> User:
    user = getattr(request.state, "secscan_user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def mount_projects(app: FastAPI, *, database: Path) -> FastAPI:
    store = ProjectStore(database)

    @app.get("/api/v1/projects")
    def list_projects(request: Request) -> list[dict[str, object]]:
        try:
            return [project.public() for project in store.list(_current_user(request))]
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/projects", status_code=201)
    def create_project(request: Request, body: ProjectCreateRequest) -> dict[str, object]:
        try:
            return store.create(_current_user(request), body.name).public()
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/projects/{project_id}")
    def get_project(project_id: str, request: Request) -> dict[str, object]:
        try:
            return store.get(_current_user(request), project_id).public()
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="project was not found") from exc

    @app.patch("/api/v1/projects/{project_id}")
    def update_project(
        project_id: str, request: Request, body: ProjectUpdateRequest
    ) -> dict[str, object]:
        if body.name is None and body.enabled is None:
            raise HTTPException(status_code=422, detail="at least one project field is required")
        try:
            return store.update(
                _current_user(request), project_id, name=body.name, enabled=body.enabled
            ).public()
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            message = str(exc)
            status = 404 if message == "project was not found" else 422
            raise HTTPException(status_code=status, detail=message) from exc

    return app
