from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.kev import enrich_finding_documents, load_kev_catalog


def _catalog(path: Path) -> Path:
    payload = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "test",
        "dateReleased": "2026-08-28T00:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Example vulnerability",
                "dateAdded": "2026-08-01",
                "shortDescription": "Example",
                "requiredAction": "Apply mitigations or discontinue use.",
                "dueDate": "2026-08-20",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_and_enrich_kev_catalog(tmp_path: Path) -> None:
    catalog = load_kev_catalog(_catalog(tmp_path / "kev.json"))
    findings, count = enrich_finding_documents(
        [
            {"vulnerability_id": "cve-2024-1234", "severity": "HIGH"},
            {"vulnerability_id": "CVE-2024-9999", "severity": "CRITICAL"},
        ],
        catalog,
    )

    assert count == 1
    assert findings[0]["known_exploited"] is True
    assert findings[0]["kev"] == {
        "vulnerability_id": "CVE-2024-1234",
        "vendor_project": "Example Vendor",
        "product": "Example Product",
        "vulnerability_name": "Example vulnerability",
        "date_added": "2026-08-01",
        "due_date": "2026-08-20",
        "required_action": "Apply mitigations or discontinue use.",
        "known_ransomware_campaign_use": "Known",
    }
    assert findings[1]["known_exploited"] is False
    assert "kev" not in findings[1]


def test_catalog_requires_absolute_existing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute JSON file"):
        load_kev_catalog(Path("kev.json"))


def test_catalog_rejects_duplicate_cves(tmp_path: Path) -> None:
    path = _catalog(tmp_path / "kev.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["vulnerabilities"].append(dict(payload["vulnerabilities"][0]))
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate CVE-2024-1234"):
        load_kev_catalog(path)


def test_catalog_rejects_invalid_ransomware_state(tmp_path: Path) -> None:
    path = _catalog(tmp_path / "kev.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["vulnerabilities"][0]["knownRansomwareCampaignUse"] = "Maybe"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="must be Known or Unknown"):
        load_kev_catalog(path)
