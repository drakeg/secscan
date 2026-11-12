from __future__ import annotations

from copy import deepcopy

import pytest

from secscan.asset_context import correlate_ecr_workloads
from secscan.aws import EcrAsset


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:" + "a" * 64
ASSET = EcrAsset("123456789012", "us-east-1", "app", "sha256:" + "a" * 64, IMAGE)


def _ecs() -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_at": "2026-11-11T22:00:00+00:00",
        "workload_count": 1,
        "workloads": [{
            "account_id": "123456789012",
            "region": "us-east-1",
            "cluster": "primary",
            "service": "api",
            "immutable_image_targets": [IMAGE],
        }],
    }


def test_exact_ecr_digest_matches_configured_ecs_service() -> None:
    result = correlate_ecr_workloads(ASSET, {"ecs": _ecs()})
    assert result["configured_workloads"] == [{
        "source": "ecs",
        "account_id": "123456789012",
        "region": "us-east-1",
        "cluster": "primary",
        "service": "api",
    }]
    assert result["internet_exposure"] is None
    assert result["runtime_execution"] is None
    assert result["snapshots_observed_at"] == {"ecs": "2026-11-11T22:00:00+00:00"}


@pytest.mark.parametrize("field,other", [
    ("account_id", "210987654321"),
    ("region", "us-west-2"),
    ("immutable_image_targets", [IMAGE.replace("a" * 64, "b" * 64)]),
])
def test_other_accounts_regions_or_digests_cannot_match(field: str, other: object) -> None:
    data = _ecs()
    data["workloads"][0][field] = other
    result = correlate_ecr_workloads(ASSET, {"ecs": data})
    assert result["configured_workloads"] == []


def test_matching_eks_workload_is_identified_without_network_claims() -> None:
    data = _ecs()
    data["workloads"][0].update({"namespace": "prod", "kind": "Deployment", "name": "api"})
    data["workloads"][0].pop("service")
    result = correlate_ecr_workloads(ASSET, {"eks": data})
    assert result["configured_workloads"][0]["kind"] == "Deployment"
    assert result["configured_workloads"][0]["namespace"] == "prod"
    assert result["internet_exposure"] is None


@pytest.mark.parametrize("mutation", ["schema", "timestamp", "count", "targets", "identity", "oversize"])
def test_malformed_snapshots_fail_closed(mutation: str) -> None:
    data = _ecs()
    if mutation == "schema":
        data["schema_version"] = 2
    elif mutation == "timestamp":
        data["generated_at"] = "2026-11-11T22:00:00"
    elif mutation == "count":
        data["workload_count"] = 2
    elif mutation == "targets":
        data["workloads"][0]["immutable_image_targets"] = "image"
    elif mutation == "identity":
        data["workloads"][0]["cluster"] = None
    else:
        data["workloads"] = [deepcopy(data["workloads"][0]) for _ in range(501)]
        data["workload_count"] = 501
    with pytest.raises(ValueError):
        correlate_ecr_workloads(ASSET, {"ecs": data})


def test_unrecognized_snapshot_source_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported workload snapshot"):
        correlate_ecr_workloads(ASSET, {"other": _ecs()})


def test_missing_snapshot_means_unknown_not_no_deployment() -> None:
    result = correlate_ecr_workloads(ASSET, {})
    assert result["configured_workloads"] == []
    assert result["snapshots_observed_at"] == {}
    assert result["runtime_execution"] is None
