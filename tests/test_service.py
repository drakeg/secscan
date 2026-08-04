from __future__ import annotations

import json
from pathlib import Path
from time import sleep

from fastapi.testclient import TestClient

from secscan.service import JobManager, ScanSubmission, create_app


def test_health_endpoint(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    assert client.get("/healthz").json() == {"status": "ok"}


def test_job_lifecycle_and_artifact_download(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "secscan.json").write_text(json.dumps({"summary": {"total": 0}}), encoding="utf-8")
        return 0

    client = TestClient(create_app(job_root=tmp_path, runner=runner))
    response = client.post("/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"})
    assert response.status_code == 202
    job_id = response.json()["id"]

    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    assert job["exit_code"] == 0
    artifact = client.get(f"/api/v1/jobs/{job_id}/artifacts/secscan.json")
    assert artifact.status_code == 200
    assert artifact.json()["summary"]["total"] == 0


def test_policy_failure_is_completed_job(tmp_path: Path) -> None:
    manager = JobManager(tmp_path, lambda _args: 2, max_workers=1)
    record = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))
    for _ in range(100):
        current = manager.get(record.id)
        assert current is not None
        if current.status != "queued" and current.status != "running":
            break
        sleep(0.01)
    assert current.status == "completed"
    assert current.exit_code == 2


def test_unknown_job_returns_404(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    assert client.get("/api/v1/jobs/missing").status_code == 404
