from __future__ import annotations

from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient

from secscan.service import create_app


def test_web_dast_requires_explicit_authorization(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "web-dast", "target": "https://example.com/"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "web DAST scans require explicit authorization acknowledgement"


def test_web_dast_reuses_strict_url_validation(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "web-dast",
            "target": "https://user:secret@example.com/",
            "web_authorized": True,
        },
    )

    assert response.status_code == 422
    assert "embedded credentials" in response.json()["detail"]


def test_authorized_web_dast_job_uses_existing_job_runner(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def runner(args: list[str]) -> int:
        seen.append(args)
        return 0

    client = TestClient(create_app(job_root=tmp_path, runner=runner))
    response = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "web-dast",
            "target": "https://example.com/app?mode=test",
            "web_authorized": True,
            "timeout": 120,
        },
    )

    assert response.status_code == 202
    job_id = response.json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert job["status"] == "completed"
    assert seen
    args = seen[0]
    assert args[:3] == ["scan", "web-dast", "https://example.com/app?mode=test"]
    assert args[args.index("--timeout") + 1] == "120"
    assert "web_authorized" not in args
    assert "--web-authorized" not in args


def test_web_dast_is_available_as_job_list_filter(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    submitted = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "web-dast",
            "target": "https://example.com/",
            "web_authorized": True,
        },
    )
    assert submitted.status_code == 202

    response = client.get("/api/v1/jobs?scanner=web-dast")
    assert response.status_code == 200
    assert [job["scanner"] for job in response.json()] == ["web-dast"]
