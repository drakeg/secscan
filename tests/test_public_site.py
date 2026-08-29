from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secscan.auth import mount_auth
from secscan.public_site import PlanStore, mount_public_site


def app_for(database: Path) -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/linux-host-jobs")
    def linux_host_job() -> dict[str, bool]:
        return {"accepted": True}

    mount_public_site(app, database=database)
    mount_auth(app, database=database)
    return app


def test_anonymous_visitors_can_browse_landing_login_and_registration(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))

    landing = client.get("/")
    assert landing.status_code == 200
    assert "Find what needs fixing first" in landing.text
    assert "Free" in landing.text
    assert "Professional" in landing.text
    assert "Sign in" in landing.text
    assert "Start free" in landing.text
    assert "Create an account" in landing.text

    assert client.get("/login").status_code == 200
    registration = client.get("/register")
    assert registration.status_code == 200
    assert "Choose Free" in registration.text
    assert "Choose Professional" in registration.text


def test_authenticated_landing_replaces_registration_ctas_with_workspace_actions(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))
    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201

    landing = client.get("/")
    assert landing.status_code == 200
    assert "Open workspace" in landing.text
    assert "Plan: Free" in landing.text
    assert "Create an account" not in landing.text
    assert "Start free" not in landing.text
    assert "href='/register'" not in landing.text


def test_registration_requires_and_persists_selected_plan(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    client = TestClient(app_for(database))

    missing = client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.test", "password": "correct-horse-battery"},
    )
    assert missing.status_code == 422

    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201
    assert created.json()["plan"] == "free"
    user_id = created.json()["id"]
    assert PlanStore(database).get(user_id) == "free"

    account = client.get("/account/plan")
    assert account.status_code == 200
    assert "Current plan" in account.text
    assert "Free" in account.text


def test_free_account_can_upgrade_and_professional_unlocks_host_workflow(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))
    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201

    blocked = client.post("/api/v1/linux-host-jobs")
    assert blocked.status_code == 403
    assert "Professional plan" in blocked.json()["detail"]

    upgraded = client.put("/api/v1/account/plan", json={"plan": "professional"})
    assert upgraded.status_code == 200
    assert upgraded.json()["plan"] == "professional"

    allowed = client.post("/api/v1/linux-host-jobs")
    assert allowed.status_code == 200
    assert allowed.json() == {"accepted": True}


def test_existing_account_defaults_to_free_when_plan_column_is_added(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    from secscan.auth import AuthStore

    auth = AuthStore(database)
    user = auth.register("legacy@example.test", "correct-horse-battery")

    plans = PlanStore(database)
    assert plans.get(user.id) == "free"
    plans.migrate()
    assert plans.get(user.id) == "free"
