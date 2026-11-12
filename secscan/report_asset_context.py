"""Bind an authorized ECR scan report to pre-authorized workload evidence.

Authorization is deliberately outside this offline helper: callers must first
resolve the scan and discovery inventories within the *same* tenant. There is
no API route or inventory lookup exposed by this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from secscan.asset_context import correlate_ecr_workloads
from secscan.aws import EcrAsset


def bind_ecr_report_context(
    report: Mapping[str, Any],
    asset: EcrAsset,
    snapshots: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Annotate an ECR image report with exact, bounded workload evidence.

    Requiring an exact report image target avoids associating similarly named
    tags, repositories, accounts or regions. Findings point to one top-level
    evidence object rather than duplicating workload lists on every finding.
    """
    target = report.get("target")
    if not isinstance(target, Mapping):
        raise ValueError("report target is missing")
    if target.get("type") != "container_image" or target.get("name") != asset.image_uri:
        raise ValueError("report target does not match the authorized ECR image")

    findings = report.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("report findings must be a list of objects")
    if report.get("asset_context") is not None:
        raise ValueError("report already contains asset context")
    # Evidence parsing must succeed before an output is produced.
    evidence = correlate_ecr_workloads(asset, snapshots)

    annotated = deepcopy(dict(report))
    annotated["schema_version"] = "1.4"
    annotated["asset_context"] = evidence
    for finding in annotated["findings"]:
        finding["asset_context_ref"] = asset.image_uri
    return annotated
