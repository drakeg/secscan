from __future__ import annotations

from pathlib import Path
from threading import Event
from time import sleep

from fastapi.testclient import TestClient

from secscan.web import create_web_app


def test_web_ui_is_served_at_root(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.get("/")

    assert response.status_code == 200
    assert "secscan" in response.text
    assert "Start a security scan" in response.text
    assert "Most urgent targets" in response.text
    assert "Critical vulnerabilities" in response.text
    assert "dashboard.js" in response.text
    assert "dashboard.css" in response.text
    assert "delete_scans.js" in response.text
    assert "delete_scans.css" in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_web_assets_are_served(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    stylesheet = client.get("/styles.css")
    script = client.get("/app.js")
    dashboard_script = client.get("/dashboard.js")
    dashboard_styles = client.get("/dashboard.css")
    delete_script = client.get("/delete_scans.js")
    delete_styles = client.get("/delete_scans.css")

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
    assert dashboard_script.status_code == 200
    assert "latestPostureJobs" in dashboard_script.text
    assert "priority-targets" in dashboard_script.text
    assert "vuln-chip critical" in dashboard_script.text
    assert "https://github.com/org/repository.git" in dashboard_script.text
    assert dashboard_styles.status_code == 200
    assert ".security-dashboard-grid" in dashboard_styles.text
    assert ".priority-bar" in dashboard_styles.text
    assert delete_script.status_code == 200
    assert "/history" in delete_script.text
    assert "window.confirm" in delete_script.text
    assert "Delete scan" in delete_script.text
    assert delete_styles.status_code == 200
    assert ".danger" in delete_styles.text


def test_completed_scan_history_and_artifacts_can_be_deleted(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "secscan.json").write_text("{}", encoding="utf-8")
        return 0

    client = TestClient(create_web_app(job_root=tmp_path, runner=runner))
    submitted = client.post("/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"})
    job_id = submitted.json()["id"]

    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    job_dir = tmp_path / job_id
    assert job_dir.is_dir()
    deleted = client.delete(f"/api/v1/jobs/{job_id}/history")

    assert deleted.status_code == 204
    assert client.get(f"/api/v1/jobs/{job_id}").status_code == 404
    assert not job_dir.exists()


def test_running_scan_history_cannot_be_deleted(tmp_path: Path) -> None:
    started = Event()
    release = Event()

    def runner(_args: list[str]) -> int:
        started.set()
        release.wait(timeout=2)
        return 0

    client = TestClient(create_web_app(job_root=tmp_path, runner=runner))
    submitted = client.post("/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"})
    job_id = submitted.json()["id"]
    assert started.wait(timeout=1)

    response = client.delete(f"/api/v1/jobs/{job_id}/history")
    release.set()

    assert response.status_code == 409
    assert response.json() == {"detail": "active jobs cannot be deleted"}
    assert client.get(f"/api/v1/jobs/{job_id}").status_code == 200


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
    assert client.delete("/api/v1/jobs/missing/history").status_code == 401
