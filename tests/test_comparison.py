from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscan.compare import compare_findings, finding_fingerprint, load_baseline
from secscan.models import Finding


def finding(cve: str, package: str = "openssl", target: str = "alpine:3.20") -> Finding:
    return Finding(cve, package, "1.0", "1.1", "HIGH", "title", target, "apk", None)


def test_fingerprint_ignores_mutable_versions_and_severity() -> None:
    first = finding("CVE-2026-1")
    second = Finding("cve-2026-1", "OpenSSL", "2.0", None, "CRITICAL", "changed", "alpine:3.20", "APK", None)

    assert finding_fingerprint(first) == finding_fingerprint(second)


def test_compare_classifies_new_resolved_and_unchanged() -> None:
    baseline = {
        "findings": [
            finding("CVE-2026-1").to_dict(),
            finding("CVE-2026-2").to_dict(),
        ]
    }

    result = compare_findings(
        [finding("CVE-2026-2"), finding("CVE-2026-3")], baseline
    )

    assert result["summary"] == {"new": 1, "resolved": 1, "unchanged": 1}
    assert result["new"][0]["vulnerability_id"] == "CVE-2026-3"
    assert result["resolved"][0]["vulnerability_id"] == "CVE-2026-1"
    assert result["unchanged"][0]["vulnerability_id"] == "CVE-2026-2"


def test_load_baseline_rejects_missing_or_invalid_reports(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_baseline(tmp_path / "missing.json")

    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"summary": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="findings list"):
        load_baseline(invalid)
