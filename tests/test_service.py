from __future__ import annotations

import hashlib
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
    manifest_response = client.get(f"/api/v1/jobs/{job_id}/artifacts/artifacts.json")
    assert manifest_response.status_code == 200
    manifest = manifest_response.json()
    report_bytes = artifact.content
    assert manifest == {
        "schema_version": 1,
        "job_id": job_id,
        "artifacts": [
            {
                "name": "secscan.json",
                "size_bytes": len(report_bytes),
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
            }
        ],
    }


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


def test_artifact_manifest_is_sorted_and_excludes_unknown_files(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "trivy.json").write_text("trivy", encoding="utf-8")
        (output_dir / "secscan.html").write_text("html", encoding="utf-8")
        (output_dir / "unknown.txt").write_text("unknown", encoding="utf-8")
        return 1

    client = TestClient(create_app(job_root=tmp_path, runner=runner))
    job_id = client.post("/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"}).json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "failed":
            break
        sleep(0.01)

    manifest = client.get(f"/api/v1/jobs/{job_id}/artifacts/artifacts.json").json()
    assert [item["name"] for item in manifest["artifacts"]] == ["secscan.html", "trivy.json"]
    assert "artifacts.json" not in [item["name"] for item in manifest["artifacts"]]
    assert "unknown.txt" not in [item["name"] for item in manifest["artifacts"]]


def test_artifact_manifest_is_empty_when_runner_produces_no_files(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    job_id = client.post("/api/v1/jobs", json={"scanner": "image", "target": "alpine:3.20"}).json()["id"]
    for _ in range(100):
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] == "completed":
            break
        sleep(0.01)

    manifest = client.get(f"/api/v1/jobs/{job_id}/artifacts/artifacts.json").json()
    assert manifest["schema_version"] == 1
    assert manifest["job_id"] == job_id
    assert manifest["artifacts"] == []


def test_artifact_manifest_failure_marks_job_failed(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "artifacts.json").mkdir()
        return 0

    manager = JobManager(tmp_path, runner, max_workers=1)
    submitted = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))
    for _ in range(100):
        current = manager.get(submitted.id)
        assert current is not None
        if current.status == "failed":
            break
        sleep(0.01)

    assert current.status == "failed"
    assert current.error is not None
    assert current.error.startswith("failed to write artifact manifest:")


def test_artifact_path_rejects_unknown_name_and_escaped_directory(tmp_path: Path) -> None:
    manager = JobManager(tmp_path / "jobs", lambda _args: 0, max_workers=1)
    record = manager.submit(ScanSubmission(scanner="image", target="alpine:3.20"))

    assert manager.artifact_path(record, "../../etc/passwd") is None

    record.output_dir = str(tmp_path / "outside")
    assert manager.artifact_path(record, "secscan.json") is None


def test_service_allows_spdx_artifact_download(tmp_path: Path) -> None:
    def runner(args: list[str]) -> int:
        output_dir = Path(args[args.index("--output-dir") + 1])
        output_dir.mkdir(parents=True)
        (output_dir / "secscan.spdx.json").write_text("{}", encoding="utf-8")
        return 0

    client = TestClient(create_app(job_root=tmp_path, runner=runner))
    job_id = client.post(
        "/api/v1/jobs", json={"scanner": "sbom", "target": "/input/example.spdx.json"}
    ).json()["id"]
    for _ in range(100):
        if client.get(f"/api/v1/jobs/{job_id}").json()["status"] == "completed":
            break
        sleep(0.01)

    artifact = client.get(f"/api/v1/jobs/{job_id}/artifacts/secscan.spdx.json")
    assert artifact.status_code == 200
    assert artifact.json() == {}


def test_unknown_job_returns_404(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path, runner=lambda _args: 0))
    assert client.get("/api/v1/jobs/missing").status_code == 404


def test_allowed_input_root_accepts_local_paths_and_image_references(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = allowed / "policy.yaml"
    policy.write_text("fail_on: HIGH\n", encoding="utf-8")
    client = TestClient(
        create_app(job_root=tmp_path / "jobs", runner=lambda _args: 0, allowed_input_roots=[allowed])
    )

    local = client.post(
        "/api/v1/jobs",
        json={"scanner": "filesystem", "target": str(allowed), "policy": str(policy)},
    )
    image = client.post(
        "/api/v1/jobs",
        json={"scanner": "image", "target": "alpine:3.20"},
    )

    assert local.status_code == 202
    assert image.status_code == 202


def test_allowed_input_root_rejects_target_policy_and_baseline_outside_root(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    client = TestClient(
        create_app(job_root=tmp_path / "jobs", runner=lambda _args: 0, allowed_input_roots=[allowed])
    )

    for payload, field in (
        ({"scanner": "filesystem", "target": str(tmp_path)}, "target"),
        ({"scanner": "image", "target": "alpine:3.20", "policy": str(tmp_path / "policy.yaml")}, "policy"),
        ({"scanner": "image", "target": "alpine:3.20", "baseline": str(tmp_path / "base.json")}, "baseline"),
    ):
        response = client.post("/api/v1/jobs", json=payload)
        assert response.status_code == 422
        assert response.json()["detail"] == f"{field} is outside the configured input roots"

    assert client.get("/api/v1/jobs").json() == []


def test_allowed_input_root_rejects_traversal_and_symlink_escapes(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "link").symlink_to(outside, target_is_directory=True)
    client = TestClient(
        create_app(job_root=tmp_path / "jobs", runner=lambda _args: 0, allowed_input_roots=[allowed])
    )

    traversal = client.post(
        "/api/v1/jobs",
        json={"scanner": "filesystem", "target": str(allowed / ".." / "outside")},
    )
    symlink = client.post(
        "/api/v1/jobs",
        json={"scanner": "filesystem", "target": str(allowed / "link")},
    )
    relative = client.post(
        "/api/v1/jobs",
        json={"scanner": "filesystem", "target": "allowed"},
    )

    assert traversal.status_code == 422
    assert symlink.status_code == 422
    assert relative.status_code == 422


def test_empty_allowed_input_roots_preserve_trusted_local_behavior(tmp_path: Path) -> None:
    client = TestClient(create_app(job_root=tmp_path / "jobs", runner=lambda _args: 0))

    response = client.post(
        "/api/v1/jobs",
        json={"scanner": "filesystem", "target": str(tmp_path / "anywhere")},
    )

    assert response.status_code == 202


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
