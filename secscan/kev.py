from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class KevEntry:
    vulnerability_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date
    required_action: str
    known_ransomware_campaign_use: str

    def to_dict(self) -> dict[str, str]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added.isoformat(),
            "due_date": self.due_date.isoformat(),
            "required_action": self.required_action,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }


def _required_text(item: dict[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"KEV entry field {name!r} must be a non-empty string")
    return value.strip()


def _required_date(item: dict[str, Any], name: str) -> date:
    value = _required_text(item, name)
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"KEV entry field {name!r} must be an ISO date") from exc


def load_kev_catalog(path: Path) -> dict[str, KevEntry]:
    expanded = path.expanduser()
    if not expanded.is_absolute() or not expanded.is_file():
        raise ValueError("SECSCAN_KEV_CATALOG must point to an existing absolute JSON file")
    try:
        payload = json.loads(expanded.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("CISA KEV catalog is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("CISA KEV catalog root must be an object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV catalog must contain a vulnerabilities list")

    entries: dict[str, KevEntry] = {}
    for raw in vulnerabilities:
        if not isinstance(raw, dict):
            raise ValueError("CISA KEV vulnerabilities must be objects")
        vulnerability_id = _required_text(raw, "cveID").upper()
        if not vulnerability_id.startswith("CVE-"):
            raise ValueError("CISA KEV cveID must use the CVE identifier format")
        if vulnerability_id in entries:
            raise ValueError(f"CISA KEV catalog contains duplicate {vulnerability_id}")
        ransomware = _required_text(raw, "knownRansomwareCampaignUse")
        if ransomware not in {"Known", "Unknown"}:
            raise ValueError("knownRansomwareCampaignUse must be Known or Unknown")
        entries[vulnerability_id] = KevEntry(
            vulnerability_id=vulnerability_id,
            vendor_project=_required_text(raw, "vendorProject"),
            product=_required_text(raw, "product"),
            vulnerability_name=_required_text(raw, "vulnerabilityName"),
            date_added=_required_date(raw, "dateAdded"),
            due_date=_required_date(raw, "dueDate"),
            required_action=_required_text(raw, "requiredAction"),
            known_ransomware_campaign_use=ransomware,
        )
    return entries


def enrich_finding_documents(
    findings: list[dict[str, Any]], catalog: dict[str, KevEntry]
) -> tuple[list[dict[str, Any]], int]:
    enriched: list[dict[str, Any]] = []
    known_exploited_count = 0
    for finding in findings:
        document = dict(finding)
        vulnerability_id = document.get("vulnerability_id")
        entry = catalog.get(vulnerability_id.upper()) if isinstance(vulnerability_id, str) else None
        if entry is None:
            document["known_exploited"] = False
        else:
            known_exploited_count += 1
            document["known_exploited"] = True
            document["kev"] = entry.to_dict()
        enriched.append(document)
    return enriched, known_exploited_count
