from __future__ import annotations

import json
from pathlib import Path
from threading import Event
from time import sleep, time

from fastapi.testclient import TestClient

from secscan.service import JobManager, JobRecord, JobStore, ScanSubmission, create_app


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


def test_artifact_path_rejects_unknown_name_and_escaped_directory(tmp_path: Path) -> None:
    manager = JobManager(tmp_path / "jobs", lambda _args: 0, max_workers=1)
    record = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))

    assert manager.artifact_path(record, "../../etc/passwd") is None

    record.output_dir = str(tmp_path / "outside")
    assert manager.artifact_path(record, "secscan.json") is None


def test_unknown_job_returns_404(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    assert client.get("/api/v1/jobs/missing").status_code == 404


def test_jobs_persist_across_manager_restart(tmp_path: Path) -> None:
    manager = JobManager(tmp_path, lambda _args: 0, max_workers=1)
    submitted = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))
    deadline = time() + 2
    while time() < deadline:
        current = manager.get(submitted.id)
        assert current is not None
        if current.status == "completed":
            break
        sleep(0.01)

    restarted = JobManager(tmp_path, lambda _args: 0, max_workers=1)
    persisted = restarted.get(submitted.id)
    assert persisted is not None
    assert persisted.status == "completed"
    assert persisted.exit_code == 0


def test_interrupted_jobs_are_failed_on_restart(tmp_path: Path) -> None:
    record = JobRecord(
        id="interrupted-job",
        status="running",
        scanner="image",
        target="alpine:3.20",
        output_dir=str(tmp_path / "interrupted-job"),
        created_at="2026-08-03T00:00:00+00:00",
    )
    JobStore(tmp_path / "jobs.db").save(record)

    restarted = JobManager(tmp_path, lambda _args: 0, max_workers=1)
    recovered = restarted.get(record.id)
    assert recovered is not None
    assert recovered.status == "failed"
    assert recovered.error == "service restarted before the job completed"


def test_list_jobs_filters_and_limits_results(tmp_path: Path) -> None:
    manager = JobManager(tmp_path, lambda _args: 0, max_workers=1)
    first = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))
    second = manager.submit(ScanSubmission(scanner="filesystem", target="."))

    deadline = time() + 2
    while time() < deadline:
        if all(manager.get(job_id).status == "completed" for job_id in (first.id, second.id)):  # type: ignore[union-attr]
            break
        sleep(0.01)

    assert [job.id for job in manager.list(scanner="filesystem")] == [second.id]
    assert len(manager.list(status="completed", limit=1)) == 1


def test_only_queued_jobs_can_be_cancelled(tmp_path: Path) -> None:
    release = Event()

    def runner(_args: list[str]) -> int:
        release.wait(timeout=2)
        return 0

    manager = JobManager(tmp_path, runner, max_workers=1)
    running = manager.submit(ScanSubmission(scanner="image", target="first"))
    deadline = time() + 2
    while time() < deadline:
        current = manager.get(running.id)
        assert current is not None
        if current.status == "running":
            break
        sleep(0.01)
    queued = manager.submit(ScanSubmission(scanner="image", target="second"))

    cancelled = manager.cancel(queued.id)
    assert cancelled is not None
    assert cancelled.status == "cancelled"
    try:
        manager.cancel(running.id)
    except ValueError as exc:
        assert str(exc) == "only queued jobs can be cancelled"
    else:
        raise AssertionError("running job cancellation should be rejected")
    release.set()


def test_job_list_and_cancel_endpoints(tmp_path: Path) -> None:
    release = Event()

    def runner(_args: list[str]) -> int:
        release.wait(timeout=2)
        return 0

    client = TestClient(create_app(job_root=tmp_path, runner=runner, max_workers=1))
    first = client.post("/api/v1/jobs", json={"scanner": "image", "target": "first"}).json()
    deadline = time() + 2
    while time() < deadline:
        if client.get(f"/api/v1/jobs/{first['id']}").json()["status"] == "running":
            break
        sleep(0.01)
    second = client.post("/api/v1/jobs", json={"scanner": "image", "target": "second"}).json()

    response = client.get("/api/v1/jobs", params={"status": "queued", "scanner": "image"})
    assert response.status_code == 200
    assert [job["id"] for job in response.json()] == [second["id"]]
    assert client.delete(f"/api/v1/jobs/{second['id']}").json()["status"] == "cancelled"
    assert client.delete(f"/api/v1/jobs/{first['id']}").status_code == 409
    assert client.delete("/api/v1/jobs/missing").status_code == 404
    release.set()
