from __future__ import annotations

from contextvars import ContextVar, Token
from pathlib import Path
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from secscan.auth import AuthStore, SESSION_COOKIE
from secscan.ssh_credential_lifecycle import SshCredentialLifecycleStore
from secscan.tenant_api_keys import TenantApiKeyStore
from secscan.tenancy import SYSTEM_TENANT_ID

_credential_tenant: ContextVar[str] = ContextVar(
    "secscan_credential_tenant", default=SYSTEM_TENANT_ID
)


def current_credential_tenant() -> str:
    return _credential_tenant.get()


def set_credential_tenant(tenant_id: str) -> Token[str]:
    return _credential_tenant.set(tenant_id)


def reset_credential_tenant(token: Token[str]) -> None:
    _credential_tenant.reset(token)


class SshCredentialTenantMiddleware(BaseHTTPMiddleware):
    """Bind encrypted SSH credential operations to the authenticated session tenant."""

    def __init__(self, app: ASGIApp, database: Path) -> None:
        super().__init__(app)
        self.database = database.expanduser().resolve()
        self.auth = AuthStore(database)
        self.api_keys = TenantApiKeyStore(database)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        session_user = self.auth.user_for_session(request.cookies.get(SESSION_COOKIE))
        api_key_user = None
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            secret = authorization[7:]
            if secret.startswith("secscan_"):
                api_key_user = self.api_keys.authenticate(secret)
                if api_key_user is None:
                    return JSONResponse(status_code=401, content={"detail": "invalid API key"})
        actor = api_key_user or session_user
        tenant_id = actor.tenant_id if actor is not None else SYSTEM_TENANT_ID
        token = set_credential_tenant(tenant_id)
        try:
            credential_path = request.url.path.startswith("/api/v1/ssh-credentials")
            is_admin_write = credential_path and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            if is_admin_write and api_key_user is not None:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "session authentication required"},
                )
            if (
                session_user is not None
                and is_admin_write
                and self.auth.membership_role(session_user.id, tenant_id) != "owner"
            ):
                return JSONResponse(status_code=403, content={"detail": "tenant owner access required"})

            if request.url.path == "/api/v1/linux-host-jobs" and request.method == "POST":
                try:
                    payload = await request.json()
                except ValueError:
                    payload = None
                requested_profile_id = (
                    payload.get("credential_profile_id") if isinstance(payload, dict) else None
                )
                if isinstance(requested_profile_id, str) and requested_profile_id:
                    lifecycle = SshCredentialLifecycleStore(self.database)
                    if not lifecycle.is_enabled(tenant_id, requested_profile_id):
                        return JSONResponse(
                            status_code=422,
                            content={"detail": "SSH credential profile is disabled"},
                        )
            return await call_next(request)
        finally:
            reset_credential_tenant(token)
