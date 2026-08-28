from __future__ import annotations

import csv
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
import re
from typing import Any

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class EpssEntry:
    vulnerability_id: str
    score: float
    percentile: float

    def to_dict(self) -> dict[str, float]:
        return {"score": self.score, "percentile": self.percentile}


def _probability(value: str, field: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"EPSS {field} must be a number between 0 and 1") from exc
    if not isfinite(parsed) or not 0.0 <= parsed <= 1.0:
        raise ValueError(f"EPSS {field} must be a number between 0 and 1")
    return parsed


def load_epss_scores(path: Path) -> dict[str, EpssEntry]:
    expanded = path.expanduser()
    if not expanded.is_absolute() or not expanded.is_file():
        raise ValueError("SECSCAN_EPSS_CSV must point to an existing absolute CSV file")
    try:
        lines = expanded.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError("EPSS score file could not be read") from exc

    data_lines = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    reader = csv.DictReader(data_lines)
    if reader.fieldnames != ["cve", "epss", "percentile"]:
        raise ValueError("EPSS CSV header must be exactly: cve,epss,percentile")

    entries: dict[str, EpssEntry] = {}
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("EPSS CSV rows must contain exactly three fields")
        vulnerability_id = row["cve"].strip().upper()
        if not _CVE_RE.fullmatch(vulnerability_id):
            raise ValueError("EPSS cve field must use the CVE identifier format")
        if vulnerability_id in entries:
            raise ValueError(f"EPSS CSV contains duplicate {vulnerability_id}")
        entries[vulnerability_id] = EpssEntry(
            vulnerability_id=vulnerability_id,
            score=_probability(row["epss"].strip(), "score"),
            percentile=_probability(row["percentile"].strip(), "percentile"),
        )
    return entries


def enrich_finding_documents(
    findings: list[dict[str, Any]], scores: dict[str, EpssEntry]
) -> tuple[list[dict[str, Any]], int, float | None]:
    enriched: list[dict[str, Any]] = []
    scored_count = 0
    max_score: float | None = None
    for finding in findings:
        document = dict(finding)
        vulnerability_id = document.get("vulnerability_id")
        entry = scores.get(vulnerability_id.upper()) if isinstance(vulnerability_id, str) else None
        if entry is not None:
            scored_count += 1
            document["epss"] = entry.to_dict()
            max_score = entry.score if max_score is None else max(max_score, entry.score)
        enriched.append(document)
    return enriched, scored_count, max_score
