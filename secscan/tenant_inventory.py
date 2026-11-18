"""Tenant-partitioned storage for bounded, operator-provided AWS workload snapshots.

A submitted snapshot has not been independently verified against AWS. Never
use it to assert actual deployment, reachability, or tenant ownership.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

MAX_SNAPSHOT_BYTES = 262_144
MAX_WORKLOADS = 500
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_REGION = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]+$")
_IMAGE = re.compile(
    r"^(?P<account>[0-9]{12})\.dkr\.ecr\.(?P<region>[a-z]{2}-[a-z]+-[0-9]+)"
    r"\.amazonaws\.com/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$"
)


def validate_workload_snapshot(source: str, snapshot: object) -> dict[str, Any]:
    """Accept only bounded, well-formed discovery-shaped data; strip extra fields."""
    if source not in {"ecs", "eks"} or not isinstance(snapshot, Mapping):
        raise ValueError("unsupported workload snapshot")
    if snapshot.get("schema_version") != 1:
        raise ValueError("unsupported workload snapshot schema")
    generated_at = snapshot.get("generated_at")
    if not isinstance(generated_at, str) or len(generated_at) > 64:
        raise ValueError("workload timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("workload timestamp is invalid") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("workload timestamp requires timezone")
    workloads = snapshot.get("workloads")
    if not isinstance(workloads, list) or len(workloads) > MAX_WORKLOADS:
        raise ValueError("workload list is invalid or oversized")
    if type(snapshot.get("workload_count")) is not int or snapshot["workload_count"] != len(workloads):
        raise ValueError("workload count mismatch")
    identities: set[tuple[str, ...]] = set()
    normalized: list[dict[str, object]] = []
    for workload in workloads:
        if not isinstance(workload, Mapping):
            raise ValueError("workload entry must be an object")
        fields = ("account_id", "region", "cluster", "service") if source == "ecs" else (
            "account_id", "region", "cluster", "namespace", "kind", "name"
        )
        values = tuple(workload.get(field) for field in fields)
        if any(not isinstance(value, str) or not 1 <= len(value) <= 256 for value in values):
            raise ValueError("workload identity is invalid")
        account, region = values[:2]
        if not _ACCOUNT.fullmatch(account) or not _REGION.fullmatch(region):
            raise ValueError("workload AWS scope is invalid")
        if values in identities:
            raise ValueError("duplicate workload identity")
        identities.add(values)
        targets = workload.get("immutable_image_targets")
        if not isinstance(targets, list) or len(targets) > 100:
            raise ValueError("workload image targets are invalid")
        valid_targets: list[str] = []
        for item in targets:
            if not isinstance(item, str):
                raise ValueError("workload image target is invalid")
            image = _IMAGE.fullmatch(item)
            if image is None or image.group("account") != account or image.group("region") != region:
                raise ValueError("workload image target AWS scope mismatch")
            valid_targets.append(item)
        if len(valid_targets) != len(set(valid_targets)):
            raise ValueError("duplicate workload image target")
        normalized.append({
            **dict(zip(fields, values, strict=True)),
            "immutable_image_targets": valid_targets,
        })
    return {
        "schema_version": 1,
        "generated_at": timestamp.isoformat(),
        "workload_count": len(normalized),
        "workloads": normalized,
    }


class TenantWorkloadInventoryStore:
    def __init__(self, database: Path) -> None:
        self.database = database
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS tenant_workload_inventory (
                    tenant_id TEXT NOT NULL,
                    source TEXT NOT NULL CHECK (source IN ('ecs', 'eks')),
                    snapshot_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, source)
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def put(self, tenant_id: str, source: str, snapshot: object) -> dict[str, Any]:
        if not tenant_id:
            raise ValueError("authenticated tenant is required")
        cleaned = validate_workload_snapshot(source, snapshot)
        serialized = json.dumps(cleaned, sort_keys=True)
        if len(serialized.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise ValueError("normalized workload snapshot is too large")
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO tenant_workload_inventory (tenant_id, source, snapshot_json)
                VALUES (?, ?, ?)
                ON CONFLICT(tenant_id, source)
                DO UPDATE SET snapshot_json = excluded.snapshot_json""",
                (tenant_id, source, serialized),
            )
        return cleaned

    def get(self, tenant_id: str, source: str) -> dict[str, Any] | None:
        if not tenant_id or source not in {"ecs", "eks"}:
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT snapshot_json FROM tenant_workload_inventory WHERE tenant_id = ? AND source = ?",
                (tenant_id, source),
            ).fetchone()
        return json.loads(row["snapshot_json"]) if row is not None else None
