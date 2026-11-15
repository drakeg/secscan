from __future__ import annotations

from copy import deepcopy

import pytest

from secscan.asset_context_view import read_report_asset_context


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/api@sha256:" + "a" * 64


def _report() -> dict[str, object]:
    return {
        "schema_version": "1.4",
        "target": {"type": "container_image", "name": IMAGE},
        "asset_context": {
            "image_uri": IMAGE,
            "account_id": "123456789012",
            "region": "us-east-1",
            "configured_workloads": [
                {
                    "source": "ecs",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "cluster": "production",
                    "service": "api",
                }
            ],
            "snapshots_observed_at": {"ecs": "2026-11-12T18:00:00+00:00"},
            "internet_exposure": None,
            "runtime_execution": None,
        },
    }


def test_valid_context_preserves_allowlisted_evidence() -> None:
    report = _report()
    original = deepcopy(report)
    result = read_report_asset_context(report, IMAGE)
    assert report == original
    assert result["configured_workloads"][0]["service"] == "api"
    assert result["snapshots_observed_at"]["ecs"] == "2026-11-12T18:00:00+00:00"
    assert result["internet_exposure"] is None


@pytest.mark.parametrize("field,value", [
    ("account_id", "999999999999"),
    ("region", "eu-west-1"),
])
def test_mismatched_context_scope_fails_closed(field: str, value: str) -> None:
    report = _report()
    report["asset_context"][field] = value
    with pytest.raises(ValueError, match="scope mismatch"):
        read_report_asset_context(report, IMAGE)


@pytest.mark.parametrize("field,value", [
    ("account_id", "999999999999"),
    ("region", "us-west-2"),
])
def test_forged_workload_scope_fails_closed(field: str, value: str) -> None:
    report = _report()
    report["asset_context"]["configured_workloads"][0][field] = value
    with pytest.raises(ValueError, match="identity is malformed"):
        read_report_asset_context(report, IMAGE)


@pytest.mark.parametrize("timestamp", [
    "2026-11-12T18:00:00",
    "nonsense",
    "X" * 65,
    123,
])
def test_invalid_provenance_timestamp_is_rejected(timestamp: object) -> None:
    report = _report()
    report["asset_context"]["snapshots_observed_at"]["ecs"] = timestamp
    with pytest.raises(ValueError, match="timestamp"):
        read_report_asset_context(report, IMAGE)


def test_missing_source_timestamp_is_rejected() -> None:
    report = _report()
    report["asset_context"]["snapshots_observed_at"] = {}
    with pytest.raises(ValueError, match="no source timestamp"):
        read_report_asset_context(report, IMAGE)


def test_duplicate_workload_references_are_rejected() -> None:
    report = _report()
    refs = report["asset_context"]["configured_workloads"]
    refs.append(dict(refs[0]))
    with pytest.raises(ValueError, match="duplicate"):
        read_report_asset_context(report, IMAGE)


def test_invalid_or_tagged_job_target_is_rejected() -> None:
    with pytest.raises(ValueError, match="immutable ECR"):
        read_report_asset_context(_report(), "api:latest")


def test_oversized_identity_rejected() -> None:
    report = _report()
    report["asset_context"]["configured_workloads"][0]["service"] = "x" * 257
    with pytest.raises(ValueError, match="identity is malformed"):
        read_report_asset_context(report, IMAGE)


def test_unverified_exposure_remains_rejected() -> None:
    report = _report()
    report["asset_context"]["internet_exposure"] = True
    with pytest.raises(ValueError, match="unverified"):
        read_report_asset_context(report, IMAGE)
