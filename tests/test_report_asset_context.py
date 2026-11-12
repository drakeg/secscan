from __future__ import annotations

from copy import deepcopy

import pytest

from secscan.aws import EcrAsset
from secscan.report_asset_context import bind_ecr_report_context


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/api@sha256:" + "a" * 64
ASSET = EcrAsset(
    account_id="123456789012", region="us-east-1",
    repository="api", digest="sha256:" + "a" * 64, image_uri=IMAGE,
)


def _report() -> dict[str, object]:
    return {
        "schema_version": "1.3",
        "target": {"type": "container_image", "name": IMAGE},
        "findings": [
            {"vulnerability_id": "CVE-2026-1234", "severity": "HIGH", "priority": {"tier": "medium"}},
            {"vulnerability_id": "CVE-2026-5678", "severity": "CRITICAL"},
        ],
    }


def _snapshots() -> dict[str, dict[str, object]]:
    return {
        "ecs": {
            "schema_version": 1,
            "generated_at": "2026-11-12T16:00:00+00:00",
            "workload_count": 1,
            "workloads": [
                {
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "cluster": "prod",
                    "service": "api",
                    "immutable_image_targets": [IMAGE],
                },
            ],
        },
    }


def test_context_link_uses_single_evidence_object_and_keeps_original_untouched() -> None:
    report = _report()
    original = deepcopy(report)
    result = bind_ecr_report_context(report, ASSET, _snapshots())
    assert report == original
    assert result["schema_version"] == "1.4"
    context = result["asset_context"]
    assert context["configured_workloads"][0]["service"] == "api"
    assert context["internet_exposure"] is None
    assert context["runtime_execution"] is None
    assert context["snapshots_observed_at"]["ecs"] == "2026-11-12T16:00:00+00:00"
    assert all(finding["asset_context_ref"] == IMAGE for finding in result["findings"])
    assert result["findings"][0]["priority"] == {"tier": "medium"}


@pytest.mark.parametrize(
    "target",
    [
        {"type": "repository", "name": IMAGE},
        {"type": "container_image", "name": IMAGE.replace("a" * 64, "b" * 64)},
        {"type": "container_image", "name": "api:latest"},
        {"type": "container_image", "name": ""},
        None,
    ],
)
def test_mismatched_targets_are_rejected(target: object) -> None:
    report = _report()
    report["target"] = target
    with pytest.raises(ValueError, match="report target"):
        bind_ecr_report_context(report, ASSET, _snapshots())


def test_malformed_snapshot_fails_without_modifying_report() -> None:
    report = _report()
    before = deepcopy(report)
    snapshots = _snapshots()
    snapshots["ecs"]["schema_version"] = 0
    with pytest.raises(ValueError, match="unsupported workload snapshot"):
        bind_ecr_report_context(report, ASSET, snapshots)
    assert report == before


def test_missing_snapshot_produces_no_claim_of_runtime_or_exposure() -> None:
    result = bind_ecr_report_context(_report(), ASSET, {})
    assert result["asset_context"]["configured_workloads"] == []
    assert result["asset_context"]["snapshots_observed_at"] == {}
    assert result["asset_context"]["internet_exposure"] is None


def test_existing_context_and_invalid_findings_are_rejected() -> None:
    report = _report()
    report["asset_context"] = {"untrusted": True}
    with pytest.raises(ValueError, match="already contains"):
        bind_ecr_report_context(report, ASSET, {})
    report = _report()
    report["findings"] = ["not an object"]
    with pytest.raises(ValueError, match="findings"):
        bind_ecr_report_context(report, ASSET, {})
