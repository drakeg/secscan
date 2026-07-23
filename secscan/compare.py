from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from secscan.models import Finding


def finding_fingerprint(finding: Finding) -> str:
    identity = "\x1f".join(
        (
            finding.vulnerability_id.strip().upper(),
            finding.package_name.strip().lower(),
            finding.target.strip(),
            (finding.package_type or "").strip().lower(),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def load_baseline(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"baseline report does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"baseline report is not valid JSON: {path}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("baseline report must contain a findings list")
    return payload


def compare_findings(current: list[Finding], baseline_report: dict[str, Any]) -> dict[str, Any]:
    current_by_id = {finding_fingerprint(finding): finding.to_dict() for finding in current}
    baseline_by_id: dict[str, dict[str, Any]] = {}
    for item in baseline_report.get("findings", []):
        if not isinstance(item, dict):
            continue
        required = ("vulnerability_id", "package_name", "target")
        if not all(isinstance(item.get(key), str) for key in required):
            continue
        finding = Finding(
            vulnerability_id=item["vulnerability_id"],
            package_name=item["package_name"],
            installed_version=str(item.get("installed_version", "")),
            fixed_version=item.get("fixed_version") if isinstance(item.get("fixed_version"), str) else None,
            severity=str(item.get("severity", "UNKNOWN")),
            title=str(item.get("title", "")),
            target=item["target"],
            package_type=item.get("package_type") if isinstance(item.get("package_type"), str) else None,
            primary_url=item.get("primary_url") if isinstance(item.get("primary_url"), str) else None,
        )
        baseline_by_id[finding_fingerprint(finding)] = item

    current_ids = set(current_by_id)
    baseline_ids = set(baseline_by_id)
    new_ids = sorted(current_ids - baseline_ids)
    resolved_ids = sorted(baseline_ids - current_ids)
    unchanged_ids = sorted(current_ids & baseline_ids)
    return {
        "schema_version": "1.0",
        "summary": {
            "new": len(new_ids),
            "resolved": len(resolved_ids),
            "unchanged": len(unchanged_ids),
        },
        "new": [current_by_id[item] for item in new_ids],
        "resolved": [baseline_by_id[item] for item in resolved_ids],
        "unchanged": [current_by_id[item] for item in unchanged_ids],
    }
