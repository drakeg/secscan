from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from pathlib import Path
import secrets
import sqlite3
from typing import Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from starlette.types import ASGIApp

from secscan.auth import AuthStore, SESSION_COOKIE, SessionAuthMiddleware, User


@dataclass(frozen=True)
class TenantApiKey:
    id: str
    tenant_id: str
    name: str
    created_by: str
    created_at: str
    expires_at: str | None
    revoked_at: str | None

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
        }


class TenantApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class TenantApiKeyStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        AuthStore(self.path)
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
                CREATE TABLE IF NOT EXISTS tenant_api_keys (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    secret_digest TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES auth_users(id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS tenant_api_keys_tenant_idx
                    ON tenant_api_keys(tenant_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS tenant_api_keys_active_idx
                    ON tenant_api_keys(id, revoked_at, expires_at);
                """
            )

    def create(
        self,
        *,
        actor: User,
        name: str,
        expires_in_days: int | None = None,
    ) -> tuple[TenantApiKey, str]:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("API key name is required")
        self._require_owner(actor)
        key_id = str(uuid4())
        secret = f"secscan_{key_id}.{secrets.token_urlsafe(32)}"
        created = datetime.now(UTC)
        expires = created + timedelta(days=expires_in_days) if expires_in_days is not None else None
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO tenant_api_keys
                   (id, tenant_id, name, secret_digest, created_by, created_at, expires_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    key_id,
                    actor.tenant_id,
                    clean_name,
                    _secret_digest(secret),
                    actor.id,
                    created.isoformat(),
                    expires.isoformat() if expires is not None else None,
                ),
            )
        return (
            TenantApiKey(
                key_id,
                actor.tenant_id,
                clean_name,
                actor.id,
                created.isoformat(),
                expires.isoformat() if expires is not None else None,
                None,
            ),
            secret,
        )

    def list(self, *, actor: User) -> list[TenantApiKey]:
        self._require_owner(actor)
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, tenant_id, name, created_by, created_at, expires_at, revoked_at
                   FROM tenant_api_keys
                   WHERE tenant_id = ?
                   ORDER BY created_at DESC, id""",
                (actor.tenant_id,),
            ).fetchall()
        return [_api_key(row) for row in rows]

    def revoke(self, *, actor: User, key_id: str) -> None:
        self._require_owner(actor)
        revoked_at = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE tenant_api_keys
                   SET revoked_at = COALESCE(revoked_at, ?)
                   WHERE id = ? AND tenant_id = ?""",
                (revoked_at, key_id, actor.tenant_id),
            )
        if cursor.rowcount == 0:
            raise ValueError("API key was not found")

    def authenticate(self, secret: str) -> User | None:
        key_id = _key_id(secret)
        if key_id is None:
            return None
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            row = connection.execute(
                """SELECT k.secret_digest, k.tenant_id,
                          u.id, u.email, u.role, u.enabled, u.created_at,
                          m.role AS tenant_role
                   FROM tenant_api_keys k
                   JOIN auth_users u ON u.id = k.created_by
                   JOIN auth_tenant_memberships m
                     ON m.user_id = u.id AND m.tenant_id = k.tenant_id
                   WHERE k.id = ?
                     AND k.revoked_at IS NULL
                     AND (k.expires_at IS NULL OR k.expires_at > ?)
                     AND u.enabled = 1""",
                (key_id, now),
            ).fetchone()
        if row is None or not hmac.compare_digest(str(row["secret_digest"]), _secret_digest(secret)):
            return None
        return User(
            id=str(row["id"]),
            tenant_id=str(row["tenant_id"]),
            email=str(row["email"]),
            role=str(row["role"]),
            enabled=bool(row["enabled"]),
            created_at=str(row["created_at"]),
        )

    def _require_owner(self, actor: User) -> None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT role FROM auth_tenant_memberships
                   WHERE tenant_id = ? AND user_id = ?""",
                (actor.tenant_id, actor.id),
            ).fetchone()
        if row is None or str(row["role"]) != "owner":
            raise PermissionError("tenant owner access required")


class TenantApiKeyAuthMiddleware(SessionAuthMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        store: AuthStore,
        api_token: str | None,
        api_key_store: TenantApiKeyStore,
    ) -> None:
        super().__init__(app, store=store, api_token=api_token)
        self.api_key_store = api_key_store

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            user = self.api_key_store.authenticate(authorization[7:])
            if user is not None:
                request.state.secscan_user = user
                request.state.secscan_auth_kind = "tenant_api_key"
                return await call_next(request)
        return await super().dispatch(request, call_next)


def mount_tenant_api_keys(
    app: FastAPI,
    *,
    database: Path,
    api_token: str | None = None,
) -> FastAPI:
    auth_store = AuthStore(database)
    api_key_store = TenantApiKeyStore(database)

    def session_owner(request: Request) -> User:
        user = auth_store.user_for_session(request.cookies.get(SESSION_COOKIE))
        if user is None:
            raise HTTPException(status_code=401, detail="session authentication required")
        if auth_store.membership_role(user.id, user.tenant_id) != "owner":
            raise HTTPException(status_code=403, detail="tenant owner access required")
        return user

    @app.get("/api/v1/auth/tenants/current/api-keys")
    def list_api_keys(request: Request) -> list[dict[str, object]]:
        actor = session_owner(request)
        return [item.public() for item in api_key_store.list(actor=actor)]

    @app.post("/api/v1/auth/tenants/current/api-keys", status_code=201)
    def create_api_key(
        request: Request,
        payload: TenantApiKeyCreateRequest,
    ) -> dict[str, object]:
        actor = session_owner(request)
        try:
            key, secret = api_key_store.create(
                actor=actor,
                name=payload.name,
                expires_in_days=payload.expires_in_days,
            )
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"api_key": key.public(), "secret": secret}

    @app.delete("/api/v1/auth/tenants/current/api-keys/{key_id}", status_code=204)
    def revoke_api_key(request: Request, key_id: str) -> Response:
        actor = session_owner(request)
        try:
            api_key_store.revoke(actor=actor, key_id=key_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(status_code=204)

    replaced = False
    for index, middleware in enumerate(list(app.user_middleware)):
        if middleware.cls.__name__ == SessionAuthMiddleware.__name__:
            app.user_middleware.pop(index)
            replaced = True
            break
    if not replaced:
        raise RuntimeError("SessionAuthMiddleware must be mounted before tenant API keys")
    app.add_middleware(
        TenantApiKeyAuthMiddleware,
        store=auth_store,
        api_token=api_token,
        api_key_store=api_key_store,
    )
    return app


def _secret_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _key_id(secret: str) -> str | None:
    if not secret.startswith("secscan_") or "." not in secret:
        return None
    key_id = secret[len("secscan_") :].split(".", 1)[0]
    return key_id or None


def _api_key(row: sqlite3.Row) -> TenantApiKey:
    return TenantApiKey(
        id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        name=str(row["name"]),
        created_by=str(row["created_by"]),
        created_at=str(row["created_at"]),
        expires_at=str(row["expires_at"]) if row["expires_at"] is not None else None,
        revoked_at=str(row["revoked_at"]) if row["revoked_at"] is not None else None,
    )
