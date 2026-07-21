from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secscan.models import Finding
from secscan.normalize import summarize


def build_report(image: str, findings: list[Finding], scanner: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {"type": "container_image", "name": image},
        "scanner": scanner,
        "summary": summarize(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
