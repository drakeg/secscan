from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.grype import GrypeImageScanner, _normalize_grype


def test_normalize_grype_maps_findings_to_secscan_model() -> None:
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-1234",
                    "severity": "High",
                    "description": "Example package vulnerability",
                    "fix": {"versions": ["1.2.4"]},
                    "urls": ["https://example.test/CVE-2026-1234"],
                },
                "artifact": {"name": "libexample", "version": "1.2.3", "type": "apk"},
            }
        ]
    }

    findings = _normalize_grype(payload, "example:latest")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability_id == "CVE-2026-1234"
    assert finding.package_name == "libexample"
    assert finding.installed_version == "1.2.3"
    assert finding.fixed_version == "1.2.4"
    assert finding.severity == "HIGH"
    assert finding.target == "example:latest"
    assert finding.package_type == "apk"
    assert finding.primary_url == "https://example.test/CVE-2026-1234"


def test_normalize_grype_unknown_severity_fails_closed() -> None:
    payload = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-example", "severity": "Negligible"},
                "artifact": {"name": "package", "version": "1"},
            }
        ]
    }

    assert _normalize_grype(payload, "example:latest")[0].severity == "UNKNOWN"


def test_grype_scanner_uses_fixed_json_command(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    payload = {"matches": []}

    def fake_run(args: list[str], **_kwargs: object) -> CompletedProcess[str]:
        calls.append(args)
        return CompletedProcess(args=args, returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("secscan.scanners.grype.subprocess.run", fake_run)
    scanner = GrypeImageScanner()
    result = scanner.scan(ScanRequest(scanner_name="image-grype", target="alpine:3.20", timeout_seconds=30))

    assert calls[0] == ["grype", "alpine:3.20", "-o", "json", "--only-fixed=false"]
    assert result.findings == ()
    assert result.raw == payload


def test_grype_adapter_does_not_claim_sbom_generation(tmp_path: Path) -> None:
    scanner = GrypeImageScanner()
    with pytest.raises(RuntimeError, match="does not generate SBOMs"):
        scanner.generate_sbom(
            ScanRequest(scanner_name="image-grype", target="alpine:3.20"),
            tmp_path / "sbom.json",
        )
