from __future__ import annotations

from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient
import pytest

from secscan.service import create_app


def test_network_submission_requires_explicit_authorization(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "network", "target": "localhost"},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "network scans require explicit authorization acknowledgement"}
    assert client.get("/api/v1/jobs").json() == []


def test_network_target_is_validated_before_job_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject(_target: str) -> str:
        raise ValueError("network target must be one hostname or IP address, not a URL or CIDR")

    monkeypatch.setattr("secscan.service.validate_network_target", reject)
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "network",
            "target": "https://example.com",
            "network_authorized": True,
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "network target must be one hostname or IP address, not a URL or CIDR"
    }
    assert client.get("/api/v1/jobs").json() == []


def test_authorized_network_job_runs_and_can_be_filtered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr("secscan.service.validate_network_target", lambda target: target)

    def runner(args: list[str]) -> int:
        captured.append(args)
        return 0

    client = TestClient(create_app(job_root=tmp_path, runner=runner))
    network = client.post(
        "/api/v1/jobs",
        json={
            "scanner": "network",
            "target": "network-fixture",
            "network_authorized": True,
            "fail_on": "NONE",
        },
    )
    image = client.post(
        "/api/v1/jobs",
        json={"scanner": "image", "target": "alpine:3.20"},
    )

    assert network.status_code == 202
    assert image.status_code == 202
    network_id = network.json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{network_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert job["status"] == "completed"
    assert any(args[:3] == ["scan", "network", "network-fixture"] for args in captured)
    filtered = client.get("/api/v1/jobs?scanner=network&limit=10")
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()] == [network_id]
    assert filtered.json()[0]["scanner"] == "network"


def test_existing_scanners_do_not_require_network_authorization(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "image", "target": "alpine:3.20"},
    )

    assert response.status_code == 202
