from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from secscan.web import create_web_app


def test_web_ui_is_served_at_root(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.get("/")

    assert response.status_code == 200
    assert "secscan" in response.text
    assert "Start a security scan" in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_web_assets_are_served(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    stylesheet = client.get("/styles.css")
    script = client.get("/app.js")

    assert stylesheet.status_code == 200
    assert "app-shell" in stylesheet.text
    assert "finding-table" in stylesheet.text
    assert script.status_code == 200
    assert "/api/v1/jobs" in script.text
    assert "finding-search" in script.text
    assert "secscan.diff.json" in script.text
    assert "Resolved findings" in script.text
    assert "scheduleDetailRefresh" in script.text
    assert '["queued","running"]' in script.text
    assert "setTimeout" in script.text
    assert "2000" in script.text
    assert "stopDetailPolling" in script.text


def test_web_wrapper_preserves_health_and_api_routes(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/api/v1/jobs").status_code == 200
    assert client.get("/docs").status_code == 200


def test_web_ui_remains_public_when_api_token_is_configured(tmp_path: Path) -> None:
    token = "a" * 32
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0, api_token=token))

    assert client.get("/").status_code == 200
    assert client.get("/api/v1/jobs").status_code == 401
    assert client.get("/api/v1/jobs", headers={"Authorization": f"Bearer {token}"}).status_code == 200
