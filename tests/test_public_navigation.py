from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from secscan.auth import AuthStore, SESSION_COOKIE
from secscan.public_navigation import PublicSessionNavigationMiddleware


def app_for(database: Path) -> FastAPI:
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def landing() -> str:
        return "<a href='/register'>Start free</a>"

    @app.get("/login", response_class=HTMLResponse)
    def login() -> str:
        return "Sign in"

    @app.get("/register", response_class=HTMLResponse)
    def register() -> str:
        return "Create account"

    @app.get("/app", response_class=HTMLResponse)
    def workspace() -> str:
        return "Workspace"

    app.add_middleware(PublicSessionNavigationMiddleware, database=database)
    return app


def test_session_aware_pages_are_private_and_vary_by_cookie(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert "Cookie" in response.headers["vary"]


def test_authenticated_users_do_not_get_login_or_registration_pages(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    store = AuthStore(database)
    user = store.register("operator@example.test", "correct-horse-battery")
    token = store.create_session(user.id)
    client = TestClient(app_for(database))
    client.cookies.set(SESSION_COOKIE, token)

    registration = client.get("/register", follow_redirects=False)
    login = client.get("/login", follow_redirects=False)

    assert registration.status_code == 303
    assert registration.headers["location"] == "/app"
    assert login.status_code == 303
    assert login.headers["location"] == "/app"


def test_anonymous_users_can_still_reach_registration(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))

    response = client.get("/register")

    assert response.status_code == 200
    assert "Create account" in response.text
