"""Validate persisted workload context for a tenant-authorized job report.

This parser is not an authorization boundary. Callers must first resolve the
job and its artifact through the existing tenant-scoped JobManager methods.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def read_report_asset_context(report: object, expected_target: str) -> dict[str, Any]:
    """Read bounded ECR configuration evidence without inferring runtime exposure."""
    if not isinstance(report, Mapping) or report.get("schema_version") != "1.4":
        raise ValueError("asset context report schema is unsupported")
    target = report.get("target")
    if (
        not isinstance(target, Mapping)
        or target.get("type") != "container_image"
        or target.get("name") != expected_target
    ):
        raise ValueError("asset context report target mismatch")
    context = report.get("asset_context")
    if not isinstance(context, Mapping) or context.get("image_uri") != expected_target:
        raise ValueError("asset context image mismatch")
    workloads = context.get("configured_workloads")
    timestamps = context.get("snapshots_observed_at")
    if (
        not isinstance(workloads, list)
        or len(workloads) > 1000
        or not isinstance(timestamps, Mapping)
        or set(timestamps) - {"ecs", "eks"}
    ):
        raise ValueError("asset context evidence is malformed")
    validated: list[dict[str, str]] = []
    for workload in workloads:
        if not isinstance(workload, Mapping):
            raise ValueError("asset context workload is malformed")
        source = workload.get("source")
        keys = ("source", "account_id", "region", "cluster", "service") if source == "ecs" else (
            "source", "account_id", "region", "cluster", "namespace", "kind", "name"
        )
        if source not in {"ecs", "eks"} or any(
            not isinstance(workload.get(key), str) or not workload[key] for key in keys
        ):
            raise ValueError("asset context workload identity is malformed")
        validated.append({key: str(workload[key]) for key in keys})
    for value in timestamps.values():
        if not isinstance(value, str) or not value:
            raise ValueError("asset context timestamp is malformed")
    if context.get("internet_exposure") is not None or context.get("runtime_execution") is not None:
        raise ValueError("unverified runtime or exposure evidence is not supported")
    return {
        "image_uri": expected_target,
        "configured_workloads": validated,
        "snapshots_observed_at": dict(timestamps),
        "internet_exposure": None,
        "runtime_execution": None,
    }
