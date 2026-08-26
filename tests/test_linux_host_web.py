from __future__ import annotations

from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient

from secscan.web import create_web_app


def _configure_ssh(monkeypatch, tmp_path: Path) -> None:
    key = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("test-key-placeholder\n", encoding="utf-8")
    known_hosts.write_text("host-key-placeholder\n", encoding="utf-8")
    monkeypatch.setenv("SECSCAN_SSH_USER", "secscan-audit")
    monkeypatch.setenv("SECSCAN_SSH_KEY", str(key))
    monkeypatch.setenv("SECSCAN_SSH_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("SECSCAN_SSH_PORT", "22")


def test_web_ui_offers_linux_host_without_browser_credential_fields() -> None:
    web_root = Path(__file__).parents[1] / "secscan" / "web_assets"
    html = (web_root / "index.html").read_text(encoding="utf-8")
    javascript = (web_root / "linux_host.js").read_text(encoding="utf-8")

    assert '<option value="linux-host">Linux server — Authenticated assessment</option>' in html
    assert "linux-host-authorized" in html
    assert "SECSCAN_SSH_KEY" not in html
    assert "private key" not in html.lower()
    assert 'api("/api/v1/linux-host-jobs"' in javascript
    assert "linux_host_authorized:true" in javascript
    assert "SECSCAN_SSH_KEY" not in javascript


def test_linux_host_capability_is_false_without_server_credentials(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.get("/api/v1/linux-host-capability")

    assert response.status_code == 200
    assert response.json() == {"configured": False}


def test_linux_host_submission_requires_authorization_and_configuration(tmp_path: Path) -> None:
    client = TestClient(create_web_app(job_root=tmp_path, runner=lambda _args: 0))

    unauthorized = client.post(
        "/api/v1/linux-host-jobs",
        json={"target": "server.example.com", "linux_host_authorized": False},
    )
    unconfigured = client.post(
        "/api/v1/linux-host-jobs",
        json={"target": "server.example.com", "linux_host_authorized": True},
    )

    assert unauthorized.status_code == 422
    assert "authorization acknowledgement" in unauthorized.json()["detail"]
    assert unconfigured.status_code == 422
    assert "server-side SECSCAN_SSH_*" in unconfigured.json()["detail"]
    assert client.get("/api/v1/jobs").json() == []


def test_configured_linux_host_submission_uses_normal_job_pipeline(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_ssh(monkeypatch, tmp_path)
    captured: list[list[str]] = []

    def runner(args: list[str]) -> int:
        captured.append(args)
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "secscan.json").write_text(
            '{"findings": [], "summary": {"total": 0}}', encoding="utf-8"
        )
        return 0

    client = TestClient(create_web_app(job_root=tmp_path / "jobs", runner=runner))
    assert client.get("/api/v1/linux-host-capability").json() == {"configured": True}

    submitted = client.post(
        "/api/v1/linux-host-jobs",
        json={
            "target": "192.0.2.10",
            "linux_host_authorized": True,
            "timeout": 321,
            "fail_on": "HIGH",
        },
    )
    assert submitted.status_code == 202
    job_id = submitted.json()["id"]

    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert job["scanner"] == "linux-host"
    assert job["target"] == "192.0.2.10"
    assert captured
    assert captured[0][:3] == ["scan", "linux-host", "192.0.2.10"]
    assert captured[0][captured[0].index("--timeout") + 1] == "321"
    assert captured[0][captured[0].index("--fail-on") + 1] == "HIGH"
    assert client.get(f"/api/v1/jobs/{job_id}/summary").json()["total"] == 0


def test_linux_host_web_rejects_url_target_before_job_persistence(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_ssh(monkeypatch, tmp_path)
    client = TestClient(create_web_app(job_root=tmp_path / "jobs", runner=lambda _args: 0))

    response = client.post(
        "/api/v1/linux-host-jobs",
        json={"target": "https://example.com", "linux_host_authorized": True},
    )

    assert response.status_code == 422
    assert client.get("/api/v1/jobs").json() == []


def test_compose_mounts_linux_host_credentials_read_only_for_service() -> None:
    compose = (Path(__file__).parents[1] / "compose.yaml").read_text(encoding="utf-8")

    assert "${SECSCAN_SSH_DIR:-./.secscan-ssh}:/run/secscan-ssh:ro" in compose
    assert 'SECSCAN_SSH_KEY: "${SECSCAN_SSH_KEY:-/run/secscan-ssh/id_ed25519}"' in compose
    assert (
        'SECSCAN_SSH_KNOWN_HOSTS: "${SECSCAN_SSH_KNOWN_HOSTS:-/run/secscan-ssh/known_hosts}"'
        in compose
    )
