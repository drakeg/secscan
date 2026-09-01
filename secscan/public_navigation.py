from __future__ import annotations

from pathlib import Path
from typing import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from secscan.auth import AuthStore, SESSION_COOKIE


_SESSION_AWARE_PATHS = {"/", "/login", "/register", "/account/plan"}


class PublicSessionNavigationMiddleware(BaseHTTPMiddleware):
    """Keep public/account navigation consistent with the current session."""

    def __init__(self, app: ASGIApp, database: Path) -> None:
        super().__init__(app)
        self.auth = AuthStore(database)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        user = None
        if path in _SESSION_AWARE_PATHS:
            user = self.auth.user_for_session(request.cookies.get(SESSION_COOKIE))

        if user is not None and path in {"/login", "/register"}:
            return RedirectResponse("/app", status_code=303)

        response = await call_next(request)
        if path in _SESSION_AWARE_PATHS:
            response.headers["Cache-Control"] = "private, no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            vary = {item.strip() for item in response.headers.get("Vary", "").split(",") if item.strip()}
            vary.add("Cookie")
            response.headers["Vary"] = ", ".join(sorted(vary))
        return response
