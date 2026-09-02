from __future__ import annotations

from contextvars import ContextVar, Token
from pathlib import Path

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from secscan.auth import AuthStore, SESSION_COOKIE
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
        self.auth = AuthStore(database)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        user = self.auth.user_for_session(request.cookies.get(SESSION_COOKIE))
        tenant_id = user.tenant_id if user is not None else SYSTEM_TENANT_ID
        token = set_credential_tenant(tenant_id)
        try:
            return await call_next(request)
        finally:
            reset_credential_tenant(token)
