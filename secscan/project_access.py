from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
from typing import Literal, cast

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from secscan.auth import AuthStore, User
from secscan.projects import Project, ProjectStore

ProjectRole = Literal["viewer", "operator"]


@dataclass(frozen=True)
class ProjectMembership:
    project_id: str
    user_id: str
    email: str
    role: ProjectRole
    created_at: str
    updated_at: str

    def public(self) -> dict[str, str]:
        return {
            "project_id": self.project_id,
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ProjectMembershipRequest(BaseModel):
    user_id: str
    role: ProjectRole


class ProjectAccessStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.auth = AuthStore(self.path)
        self.projects = ProjectStore(self.path)
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
                CREATE TABLE IF NOT EXISTS project_memberships (
                    project_id TEXT NOT NULL REFERENCES tenant_projects(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    role TEXT NOT NULL CHECK(role IN ('viewer', 'operator')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, user_id)
                );
                CREATE INDEX IF NOT EXISTS project_memberships_user_project_idx
                    ON project_memberships(user_id, project_id);
                """
            )

    def _require_owner_project(self, actor: User, project_id: str) -> Project:
        if self.auth.membership_role(actor.id, actor.tenant_id) != "owner":
            raise PermissionError("tenant owner access required")
        return self.projects.get(actor, project_id)

    def _has_explicit_acl(self, project_id: str) -> bool:
        with self._connect() as connection:
            return connection.execute(
                "SELECT 1 FROM project_memberships WHERE project_id = ? LIMIT 1", (project_id,)
            ).fetchone() is not None

    def role(self, actor: User, project_id: str) -> ProjectRole | Literal["owner", "member"] | None:
        project = self.projects.get(actor, project_id)
        tenant_role = self.auth.membership_role(actor.id, project.tenant_id)
        if tenant_role == "owner":
            return "owner"
        with self._connect() as connection:
            row = connection.execute(
                "SELECT role FROM project_memberships WHERE project_id = ? AND user_id = ?",
                (project_id, actor.id),
            ).fetchone()
        if row is not None:
            return cast(ProjectRole, str(row["role"]))
        if not self._has_explicit_acl(project_id):
            return "member"
        return None

    def require_read(self, actor: User, project_id: str) -> Project:
        project = self.projects.get(actor, project_id)
        if self.role(actor, project_id) is None:
            raise ValueError("project was not found")
        return project

    def require_operator(self, actor: User, project_id: str) -> Project:
        project = self.projects.get(actor, project_id, require_enabled=True)
        role = self.role(actor, project_id)
        if role not in {"owner", "operator", "member"}:
            raise ValueError("project was not found")
        return project

    def list_members(self, actor: User, project_id: str) -> list[ProjectMembership]:
        self._require_owner_project(actor, project_id)
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT pm.project_id, pm.user_id, u.email, pm.role,
                          pm.created_at, pm.updated_at
                   FROM project_memberships pm
                   JOIN auth_users u ON u.id = pm.user_id
                   WHERE pm.project_id = ?
                   ORDER BY u.email COLLATE NOCASE, pm.user_id""",
                (project_id,),
            ).fetchall()
        return [_membership(row) for row in rows]

    def grant(self, actor: User, project_id: str, user_id: str, role: ProjectRole) -> ProjectMembership:
        project = self._require_owner_project(actor, project_id)
        if self.auth.membership_role(user_id, project.tenant_id) is None:
            raise ValueError("tenant member was not found")
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            user = connection.execute(
                "SELECT email FROM auth_users WHERE id = ? AND enabled = 1", (user_id,)
            ).fetchone()
            if user is None:
                raise ValueError("tenant member was not found")
            existing = connection.execute(
                "SELECT created_at FROM project_memberships WHERE project_id = ? AND user_id = ?",
                (project_id, user_id),
            ).fetchone()
            created_at = now if existing is None else str(existing["created_at"])
            connection.execute(
                """INSERT INTO project_memberships (project_id, user_id, role, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(project_id, user_id) DO UPDATE SET
                       role = excluded.role, updated_at = excluded.updated_at""",
                (project_id, user_id, role, created_at, now),
            )
        return ProjectMembership(project_id, user_id, str(user["email"]), role, created_at, now)

    def revoke(self, actor: User, project_id: str, user_id: str) -> None:
        self._require_owner_project(actor, project_id)
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM project_memberships WHERE project_id = ? AND user_id = ?",
                (project_id, user_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("project member was not found")


def _membership(row: sqlite3.Row) -> ProjectMembership:
    return ProjectMembership(
        project_id=str(row["project_id"]),
        user_id=str(row["user_id"]),
        email=str(row["email"]),
        role=cast(ProjectRole, str(row["role"])),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _current_user(request: Request) -> User:
    user = getattr(request.state, "secscan_user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def mount_project_access(app: FastAPI, *, database: Path) -> FastAPI:
    store = ProjectAccessStore(database)

    @app.get("/api/v1/projects/{project_id}/members")
    def list_project_members(project_id: str, request: Request) -> list[dict[str, str]]:
        try:
            return [item.public() for item in store.list_members(_current_user(request), project_id)]
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="project was not found") from exc

    @app.put("/api/v1/projects/{project_id}/members/{user_id}")
    def grant_project_member(
        project_id: str, user_id: str, request: Request, body: ProjectMembershipRequest
    ) -> dict[str, str]:
        if body.user_id != user_id:
            raise HTTPException(status_code=422, detail="project member identity does not match path")
        try:
            return store.grant(_current_user(request), project_id, user_id, body.role).public()
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            message = str(exc)
            status = 404 if message in {"project was not found", "tenant member was not found"} else 422
            raise HTTPException(status_code=status, detail=message) from exc

    @app.delete("/api/v1/projects/{project_id}/members/{user_id}", status_code=204)
    def revoke_project_member(project_id: str, user_id: str, request: Request) -> None:
        try:
            store.revoke(_current_user(request), project_id, user_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app
