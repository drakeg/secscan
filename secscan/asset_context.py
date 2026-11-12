"""Bounded, read-only correlation of ECR images with discovered workload snapshots.

Callers must authorize and scope inventory snapshots before using this helper.
A matching image reference is *configuration evidence*, not proof of deployment,
running state, network reachability, or tenant ownership.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from secscan.aws import EcrAsset

MAX_WORKLOADS_PER_SNAPSHOT = 500


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("workload snapshot must include a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("workload snapshot timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("workload snapshot timestamp needs a timezone")
    return parsed.isoformat()


def correlate_ecr_workloads(
    asset: EcrAsset,
    snapshots: Mapping[str, Mapping[str, Any]],
) -> dict[str, object]:
    """Match exact account/region/immutable URI across approved ECS/EKS snapshots.

    Only the known sources "ecs" and "eks" are accepted. An incomplete,
    malformed, or oversized snapshot is rejected rather than silently treated
    as no evidence.
    """
    if set(snapshots) - {"ecs", "eks"}:
        raise ValueError("unsupported workload snapshot source")
    associations: list[dict[str, str]] = []
    observed_at: dict[str, str] = {}
    for source in ("ecs", "eks"):
        if source not in snapshots:
            continue
        snapshot = snapshots[source]
        if snapshot.get("schema_version") != 1:
            raise ValueError("unsupported workload snapshot schema")
        observed_at[source] = _timestamp(snapshot.get("generated_at"))
        workloads = snapshot.get("workloads")
        if not isinstance(workloads, list) or len(workloads) > MAX_WORKLOADS_PER_SNAPSHOT:
            raise ValueError("workload snapshot must contain a bounded workload list")
        if snapshot.get("workload_count") != len(workloads):
            raise ValueError("workload snapshot count is inconsistent")
        for workload in workloads:
            if not isinstance(workload, Mapping):
                raise ValueError("workload must be an object")
            account = workload.get("account_id")
            region = workload.get("region")
            targets = workload.get("immutable_image_targets")
            if not isinstance(account, str) or not isinstance(region, str):
                raise ValueError("workload scope is invalid")
            if not isinstance(targets, list) or any(not isinstance(t, str) for t in targets):
                raise ValueError("workload immutable targets are invalid")
            if account != asset.account_id or region != asset.region:
                continue
            if asset.image_uri not in targets:
                continue
            required: tuple[str, ...]
            if source == "ecs":
                required = ("cluster", "service")
            else:
                required = ("cluster", "namespace", "kind", "name")
            if any(not isinstance(workload.get(key), str) or not workload[key] for key in required):
                raise ValueError("matched workload identity is invalid")
            link = {"source": source, "account_id": account, "region": region}
            link.update({key: str(workload[key]) for key in required})
            associations.append(link)
    associations.sort(key=lambda item: tuple(item.get(key, "") for key in (
        "source", "account_id", "region", "cluster", "namespace", "kind", "name", "service"
    )))
    return {
        "image_uri": asset.image_uri,
        "account_id": asset.account_id,
        "region": asset.region,
        "configured_workloads": associations,
        "snapshots_observed_at": observed_at,
        "internet_exposure": None,
        "runtime_execution": None,
    }
