from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import secrets
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from secscan.auth import User, normalize_email

INVITATION_HOURS = 72


@dataclass(frozen=True)
class TenantInvitation:
    id: str
    tenant_id: str
    email: str
    role: str
    created_by: str
    created_at: str
    expires_at: str
    accepted_at: str | None
    revoked_at: str | None

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "accepted_at": self.accepted_at,
            "revoked_at": self.revoked_at,
        }


class InvitationCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class InvitationAcceptRequest(BaseModel):
    token: str = Field(min_length=32, max_length=512)


class TenantInvitationStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_tenant_invitations (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role = 'member'),
                    token_hash TEXT NOT NULL UNIQUE,
                    created_by TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    accepted_at TEXT,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS auth_tenant_invites_tenant_idx
                    ON auth_tenant_invitations(tenant_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS auth_tenant_invites_email_idx
                    ON auth_tenant_invitations(tenant_id, email);
                CREATE TRIGGER IF NOT EXISTS auth_tenant_invites_revoke_on_membership_insert
                AFTER INSERT ON auth_tenant_memberships
                BEGIN
                    UPDATE auth_tenant_invitations
                    SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    WHERE tenant_id = NEW.tenant_id
                      AND email = (SELECT email FROM auth_users WHERE id = NEW.user_id)
                      AND accepted_at IS NULL
                      AND revoked_at IS NULL;
                END;
                """
            )

    @staticmethod
    def _invitation(row: sqlite3.Row) -> TenantInvitation:
        return TenantInvitation(
            id=str(row["id"]), tenant_id=str(row["tenant_id"]), email=str(row["email"]),
            role=str(row["role"]), created_by=str(row["created_by"]),
            created_at=str(row["created_at"]), expires_at=str(row["expires_at"]),
            accepted_at=str(row["accepted_at"]) if row["accepted_at"] else None,
            revoked_at=str(row["revoked_at"]) if row["revoked_at"] else None,
        )

    @staticmethod
    def _require_owner(connection: sqlite3.Connection, user_id: str, tenant_id: str) -> None:
        row = connection.execute(
            "SELECT role FROM auth_tenant_memberships WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        if row is None or str(row["role"]) != "owner":
            raise PermissionError("tenant owner access required")

    def create(self, actor: User, email: str) -> tuple[TenantInvitation, str]:
        normalized = normalize_email(email)
        now = datetime.now(UTC)
        token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        invitation_id = secrets.token_hex(16)
        expires_at = now + timedelta(hours=INVITATION_HOURS)
        with self._connect() as connection:
            self._require_owner(connection, actor.id, actor.tenant_id)
            existing_member = connection.execute(
                """SELECT 1 FROM auth_tenant_memberships m JOIN auth_users u ON u.id = m.user_id
                   WHERE m.tenant_id = ? AND u.email = ?""",
                (actor.tenant_id, normalized),
            ).fetchone()
            if existing_member is not None:
                raise ValueError("account is already a member of this tenant")
            connection.execute(
                """UPDATE auth_tenant_invitations SET revoked_at = ?
                   WHERE tenant_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL""",
                (now.isoformat(), actor.tenant_id, normalized),
            )
            connection.execute(
                """INSERT INTO auth_tenant_invitations
                   (id, tenant_id, email, role, token_hash, created_by, created_at, expires_at)
                   VALUES (?, ?, ?, 'member', ?, ?, ?, ?)""",
                (invitation_id, actor.tenant_id, normalized, token_hash, actor.id,
                 now.isoformat(), expires_at.isoformat()),
            )
            row = connection.execute(
                "SELECT * FROM auth_tenant_invitations WHERE id = ?", (invitation_id,)
            ).fetchone()
        assert row is not None
        return self._invitation(row), token

    def list(self, actor: User) -> list[TenantInvitation]:
        with self._connect() as connection:
            self._require_owner(connection, actor.id, actor.tenant_id)
            rows = connection.execute(
                "SELECT * FROM auth_tenant_invitations WHERE tenant_id = ? ORDER BY created_at DESC, id",
                (actor.tenant_id,),
            ).fetchall()
        return [self._invitation(row) for row in rows]

    def revoke(self, actor: User, invitation_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            self._require_owner(connection, actor.id, actor.tenant_id)
            row = connection.execute(
                "SELECT accepted_at, revoked_at FROM auth_tenant_invitations WHERE id = ? AND tenant_id = ?",
                (invitation_id, actor.tenant_id),
            ).fetchone()
            if row is None:
                raise ValueError("invitation was not found")
            if row["accepted_at"] is not None or row["revoked_at"] is not None:
                raise ValueError("invitation is no longer active")
            connection.execute(
                "UPDATE auth_tenant_invitations SET revoked_at = ? WHERE id = ? AND tenant_id = ?",
                (now, invitation_id, actor.tenant_id),
            )

    def accept(self, actor: User, token: str) -> str:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM auth_tenant_invitations WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                raise ValueError("invitation is invalid")
            invitation = self._invitation(row)
            if invitation.revoked_at is not None or invitation.accepted_at is not None:
                raise ValueError("invitation is no longer active")
            try:
                expires_at = datetime.fromisoformat(invitation.expires_at)
            except ValueError as exc:
                raise ValueError("invitation is invalid") from exc
            if expires_at <= now:
                raise ValueError("invitation has expired")
            if normalize_email(actor.email) != invitation.email:
                raise PermissionError("invitation belongs to a different account")
            existing = connection.execute(
                "SELECT 1 FROM auth_tenant_memberships WHERE tenant_id = ? AND user_id = ?",
                (invitation.tenant_id, actor.id),
            ).fetchone()
            if existing is not None:
                raise ValueError("account is already a member of this tenant")
            connection.execute(
                "UPDATE auth_tenant_invitations SET accepted_at = ? WHERE id = ?",
                (now.isoformat(), invitation.id),
            )
            connection.execute(
                """INSERT INTO auth_tenant_memberships (tenant_id, user_id, role, created_at)
                   VALUES (?, ?, 'member', ?)""",
                (invitation.tenant_id, actor.id, now.isoformat()),
            )
        return invitation.tenant_id


def _current_user(request: Request) -> User:
    user = getattr(request.state, "secscan_user", None)
    if not isinstance(user, User):
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def mount_tenant_invitations(app: FastAPI, *, database: Path) -> FastAPI:
    store = TenantInvitationStore(database)

    @app.get("/api/v1/auth/tenants/current/invitations")
    def list_invitations(request: Request) -> list[dict[str, object]]:
        try:
            return [item.public() for item in store.list(_current_user(request))]
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/auth/tenants/current/invitations", status_code=201)
    def create_invitation(request: Request, payload: InvitationCreateRequest) -> dict[str, object]:
        try:
            invitation, token = store.create(_current_user(request), payload.email)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        result = invitation.public()
        result["token"] = token
        return result

    @app.delete("/api/v1/auth/tenants/current/invitations/{invitation_id}", status_code=204)
    def revoke_invitation(request: Request, invitation_id: str) -> None:
        try:
            store.revoke(_current_user(request), invitation_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/auth/tenant-invitations/accept")
    def accept_invitation(request: Request, payload: InvitationAcceptRequest) -> dict[str, str]:
        try:
            tenant_id = store.accept(_current_user(request), payload.token)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"tenant_id": tenant_id, "status": "accepted"}

    return app
