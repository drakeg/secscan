from __future__ import annotations

from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient
import pytest

from secscan.network_range_web import mount_network_range_submission
from secscan.scanners.network import expand_network_range
from secscan.service import create_app


def _client(tmp_path: Path, runner=lambda _args: 0) -> TestClient:  # type: ignore[no-untyped-def]
    app = create_app(job_root=tmp_path, runner=runner)
    mount_network_range_submission(app)
    return TestClient(app)


def test_network_range_requires_explicit_authorization(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/api/v1/network-range-jobs",
        json={"target": "192.0.2.0/30"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "network range scans require explicit authorization acknowledgement"
    }
    assert client.get("/api/v1/jobs").json() == []


def test_generic_job_endpoint_cannot_bypass_network_range_authorization(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "network-range", "target": "192.0.2.0/30"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "network range scans require explicit authorization acknowledgement"
    }
    assert client.get("/api/v1/jobs").json() == []


def test_network_range_rejects_large_ipv6_without_unbounded_expansion(tmp_path: Path) -> None:
    client = _client(tmp_path)

    response = client.post(
        "/api/v1/network-range-jobs",
        json={
            "target": "2001:db8::/64",
            "network_authorized": True,
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "network range exceeds maximum of 16 hosts"}
    assert client.get("/api/v1/jobs").json() == []


def test_expand_network_range_huge_ipv6_fails_at_bound() -> None:
    with pytest.raises(ValueError, match="maximum of 16"):
        expand_network_range("2001:db8::/64")


def test_authorized_network_range_uses_normal_job_pipeline(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    def runner(args: list[str]) -> int:
        captured.append(args)
        return 0

    client = _client(tmp_path, runner)
    response = client.post(
        "/api/v1/network-range-jobs",
        json={
            "target": "192.0.2.0/30",
            "network_authorized": True,
            "fail_on": "NONE",
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
    assert job["scanner"] == "network-range"
    assert any(args[:3] == ["scan", "network-range", "192.0.2.0/30"] for args in captured)
    filtered = client.get("/api/v1/jobs?scanner=network-range&limit=10")
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()] == [job_id]


def test_workspace_contains_network_range_controls() -> None:
    page = Path(__file__).parents[1] / "secscan" / "web_assets" / "index.html"
    script = Path(__file__).parents[1] / "secscan" / "web_assets" / "network_range.js"

    html = page.read_text(encoding="utf-8")
    javascript = script.read_text(encoding="utf-8")

    assert 'value="network-range"' in html
    assert 'id="network-range-authorization"' in html
    assert 'id="network-range-authorized"' in html
    assert '/network_range.js' in html
    assert '/api/v1/network-range-jobs' in javascript
