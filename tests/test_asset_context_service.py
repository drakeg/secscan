from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from fastapi import Request
from fastapi.testclient import TestClient

from secscan.aws import EcrAsset
from secscan.report_asset_context import bind_ecr_report_context
from secscan.service import JobRecord, JobStore, create_app


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/api@sha256:" + "a" * 64
ASSET = EcrAsset("123456789012", "us-east-1", "api", "sha256:" + "a" * 64, IMAGE)


def _client(tmp_path: Path) -> TestClient:
    app = create_app(job_root=tmp_path, job_database=tmp_path / "jobs.db", runner=lambda _: 0)

    @app.middleware("http")
    async def fake_authenticated_tenant(request: Request, call_next):
        # Simulate a previously authenticated tenant; this is never production auth.
        request.state.secscan_user = SimpleNamespace(tenant_id=request.headers.get("x-test-tenant", "alpha"))
        return await call_next(request)

    return TestClient(app)


def _write_job(tmp_path: Path, *, tenant: str = "alpha", report: object, job_id: str = "job1") -> None:
    job_dir = tmp_path / job_id
    job_dir.mkdir()
    (job_dir / "secscan.json").write_text(json.dumps(report), encoding="utf-8")
    JobStore(tmp_path / "jobs.db").save(JobRecord(
        id=job_id,
        status="completed",
        scanner="image",
        target=IMAGE,
        output_dir=str(job_dir),
        created_at="2026-11-12T18:00:00+00:00",
        tenant_id=tenant,
    ))


def _report() -> dict[str, object]:
    snapshot = {
        "ecs": {
            "schema_version": 1,
            "generated_at": "2026-11-12T18:00:00+00:00",
            "workload_count": 1,
            "workloads": [{
                "account_id": "123456789012",
                "region": "us-east-1",
                "cluster": "production",
                "service": "api",
                "immutable_image_targets": [IMAGE],
            }],
        },
    }
    return bind_ecr_report_context(
        {"schema_version": "1.3", "target": {"type": "container_image", "name": IMAGE}, "findings": []},
        ASSET,
        snapshot,
    )


def test_asset_context_read_is_scoped_to_authenticated_job_tenant(tmp_path: Path) -> None:
    _write_job(tmp_path, report=_report())
    client = _client(tmp_path)
    visible = client.get("/api/v1/jobs/job1/asset-context", headers={"x-test-tenant": "alpha"})
    assert visible.status_code == 200
    assert visible.json()["configured_workloads"][0]["service"] == "api"
    assert visible.json()["internet_exposure"] is None
    assert visible.headers["cache-control"] == "private, no-store"

    foreign = client.get("/api/v1/jobs/job1/asset-context", headers={"x-test-tenant": "beta"})
    assert foreign.status_code == 404
    assert foreign.json() == {"detail": "job not found"}


def test_missing_context_returns_404_not_unscoped_scan_report(tmp_path: Path) -> None:
    _write_job(tmp_path, report={"schema_version": "1.3", "target": {"type": "container_image", "name": IMAGE}})
    client = _client(tmp_path)
    response = client.get("/api/v1/jobs/job1/asset-context")
    assert response.status_code == 404
    assert response.json()["detail"] == "asset context not found"


def test_forged_report_target_and_exposure_evidence_are_not_returned(tmp_path: Path) -> None:
    report = _report()
    report["asset_context"]["internet_exposure"] = True
    _write_job(tmp_path, report=report)
    client = _client(tmp_path)
    assert client.get("/api/v1/jobs/job1/asset-context").status_code == 404

    report = _report()
    report["target"]["name"] = "another-image"
    path = tmp_path / "job1" / "secscan.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert client.get("/api/v1/jobs/job1/asset-context").status_code == 404


def test_oversized_context_artifact_is_rejected(tmp_path: Path) -> None:
    _write_job(tmp_path, report=_report())
    (tmp_path / "job1" / "secscan.json").write_text(" " * (1_048_576 + 1), encoding="utf-8")
    assert _client(tmp_path).get("/api/v1/jobs/job1/asset-context").status_code == 404
