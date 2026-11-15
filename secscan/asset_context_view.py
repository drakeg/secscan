"""Validate persisted workload context for a tenant-authorized job report.

This parser is not an authorization boundary. Callers must first resolve the
job and its artifact through the existing tenant-scoped JobManager methods.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

ECR_IMAGE = re.compile(
    r"^(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z]{2}-[a-z]+-[0-9]+)"
    r"\.amazonaws\.com/(?P<repository>[a-z0-9]+(?:[._/-][a-z0-9]+)*)"
    r"@sha256:[0-9a-f]{64}$"
)
MAX_CONTEXT_WORKLOADS = 1000
MAX_CONTEXT_TIMESTAMP_LENGTH = 64
MAX_IDENTITY_LENGTH = 256


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_CONTEXT_TIMESTAMP_LENGTH:
        raise ValueError("asset context timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("asset context timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("asset context timestamp must have a timezone")
    return parsed.isoformat()


def read_report_asset_context(report: object, expected_target: str) -> dict[str, Any]:
    """Read bounded ECR configuration evidence without inferring runtime exposure."""
    image = ECR_IMAGE.fullmatch(expected_target)
    if image is None:
        raise ValueError("job target is not an immutable ECR image")
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
    account = image.group("account")
    region = image.group("region")
    if context.get("account_id") != account or context.get("region") != region:
        raise ValueError("asset context AWS scope mismatch")
    workloads = context.get("configured_workloads")
    timestamps = context.get("snapshots_observed_at")
    if (
        not isinstance(workloads, list)
        or len(workloads) > MAX_CONTEXT_WORKLOADS
        or not isinstance(timestamps, Mapping)
        or set(timestamps) - {"ecs", "eks"}
    ):
        raise ValueError("asset context evidence is malformed")
    observed_at = {source: _timestamp(timestamp) for source, timestamp in timestamps.items()}
    validated: list[dict[str, str]] = []
    seen: set[tuple[str, ...]] = set()
    for workload in workloads:
        if not isinstance(workload, Mapping):
            raise ValueError("asset context workload is malformed")
        source = workload.get("source")
        keys: tuple[str, ...]
        if source == "ecs":
            keys = ("source", "account_id", "region", "cluster", "service")
        elif source == "eks":
            keys = ("source", "account_id", "region", "cluster", "namespace", "kind", "name")
        else:
            raise ValueError("asset context workload source is unsupported")
        if source not in observed_at:
            raise ValueError("asset context workload has no source timestamp")
        if (
            workload.get("account_id") != account
            or workload.get("region") != region
            or any(
                not isinstance(workload.get(key), str)
                or not 1 <= len(workload[key]) <= MAX_IDENTITY_LENGTH
                for key in keys
            )
        ):
            raise ValueError("asset context workload identity is malformed")
        identity = tuple(str(workload[key]) for key in keys)
        if identity in seen:
            raise ValueError("duplicate asset context workload identity")
        seen.add(identity)
        validated.append(dict(zip(keys, identity, strict=True)))
    if context.get("internet_exposure") is not None or context.get("runtime_execution") is not None:
        raise ValueError("unverified runtime or exposure evidence is not supported")
    return {
        "image_uri": expected_target,
        "configured_workloads": validated,
        "snapshots_observed_at": observed_at,
        "internet_exposure": None,
        "runtime_execution": None,
    }
