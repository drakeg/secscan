from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi import Request
from fastapi.testclient import TestClient
import pytest

from secscan.tenant_inventory import TenantWorkloadInventoryStore, validate_workload_snapshot
from secscan.service import create_app


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:" + "a" * 64


def _snapshot() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_at": "2026-11-18T12:00:00+00:00",
        "workload_count": 1,
        "workloads": [{
            "account_id": "123456789012",
            "region": "us-east-1",
            "cluster": "prod",
            "service": "api",
            "immutable_image_targets": [IMAGE],
            "untrusted_extra": "never persisted",
        }],
    }


def _client(root: Path) -> TestClient:
    app = create_app(job_root=root, job_database=root / "jobs.db", runner=lambda _: 0)

    @app.middleware("http")
    async def test_tenant(request: Request, call_next):
        # Simulate a preceding authenticated session, not a production auth provider.
        value = request.headers.get("x-test-tenant")
        if value:
            request.state.secscan_user = SimpleNamespace(tenant_id=value)
        return await call_next(request)

    return TestClient(app)


def test_tenant_upload_read_and_replacement_survive_restart(tmp_path: Path) -> None:
    client = _client(tmp_path)
    url = "/api/v1/workload-inventory/ecs"
    uploaded = client.put(url, json=_snapshot(), headers={"x-test-tenant": "alpha"})
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["provenance"] == "operator_provided_unverified"
    assert uploaded.json()["workload_count"] == 1
    assert uploaded.headers["cache-control"] == "private, no-store"

    assert client.get(url, headers={"x-test-tenant": "beta"}).status_code == 404
    read = _client(tmp_path).get(url, headers={"x-test-tenant": "alpha"})
    assert read.status_code == 200
    assert read.json()["snapshot"]["workloads"][0]["service"] == "api"
    assert "untrusted_extra" not in read.json()["snapshot"]["workloads"][0]
    assert read.json()["provenance"] == "operator_provided_unverified"

    empty = _snapshot()
    empty["workloads"] = []
    empty["workload_count"] = 0
    assert client.put(url, json=empty, headers={"x-test-tenant": "alpha"}).status_code == 200
    assert client.get(url, headers={"x-test-tenant": "alpha"}).json()["snapshot"]["workload_count"] == 0
    assert client.get(url, headers={"x-test-tenant": "beta"}).status_code == 404


def test_system_actor_cannot_use_tenant_inventory(tmp_path: Path) -> None:
    client = _client(tmp_path)
    url = "/api/v1/workload-inventory/ecs"
    assert client.put(url, json=_snapshot()).status_code == 403
    assert client.get(url).status_code == 403


def test_invalid_upload_does_not_replace_previous_snapshot(tmp_path: Path) -> None:
    client = _client(tmp_path)
    url = "/api/v1/workload-inventory/ecs"
    headers = {"x-test-tenant": "alpha"}
    assert client.put(url, json=_snapshot(), headers=headers).status_code == 200
    forged = _snapshot()
    forged["workloads"][0]["account_id"] = "999999999999"
    assert client.put(url, json=forged, headers=headers).status_code == 422
    assert client.get(url, headers=headers).json()["snapshot"]["workload_count"] == 1
    assert client.put(url, content=b"{" + b"x" * 262144, headers=headers).status_code == 413
    assert client.get(url, headers=headers).json()["snapshot"]["workloads"][0]["account_id"] == "123456789012"


@pytest.mark.parametrize("mutation", ["source", "timestamp", "count", "image", "duplicate", "identity"])
def test_malformed_inventory_is_rejected(mutation: str) -> None:
    snapshot = _snapshot()
    source = "ecs"
    if mutation == "source":
        source = "unknown"
    elif mutation == "timestamp":
        snapshot["generated_at"] = "2026-11-18T12:00:00"
    elif mutation == "count":
        snapshot["workload_count"] = 2
    elif mutation == "image":
        snapshot["workloads"][0]["immutable_image_targets"] = [
            IMAGE.replace("123456789012", "999999999999")
        ]
    elif mutation == "duplicate":
        snapshot["workloads"].append(dict(snapshot["workloads"][0]))
        snapshot["workload_count"] = 2
    else:
        snapshot["workloads"][0]["service"] = ""
    with pytest.raises(ValueError):
        validate_workload_snapshot(source, snapshot)


def test_store_prevents_cross_tenant_reads(tmp_path: Path) -> None:
    store = TenantWorkloadInventoryStore(tmp_path / "inventory.db")
    store.put("alpha", "ecs", _snapshot())
    assert store.get("beta", "ecs") is None
    assert store.get("alpha", "eks") is None
    assert store.get("alpha", "ecs") is not None
