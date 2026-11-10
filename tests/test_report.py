from pathlib import Path

from secscan.models import Finding
from secscan.report import build_report, write_html


def test_html_report_escapes_values_and_lists_fix(tmp_path: Path) -> None:
    finding = Finding(
        vulnerability_id="CVE-TEST-1",
        package_name="pkg<script>",
        installed_version="1.0",
        fixed_version="1.1",
        severity="HIGH",
        title="Unsafe <title>",
        target="alpine",
        package_type="apk",
        primary_url="https://example.com/CVE-TEST-1",
    )
    report = build_report("example:latest", [finding], {"version": "Trivy 0.test"})
    output = tmp_path / "secscan.html"

    write_html(report, output)
    rendered = output.read_text(encoding="utf-8")

    assert "pkg&lt;script&gt;" in rendered
    assert "Unsafe &lt;title&gt;" in rendered
    assert "1.1" in rendered
    assert "https://example.com/CVE-TEST-1" in rendered
    assert "<script>" not in rendered


def test_html_report_handles_no_findings(tmp_path: Path) -> None:
    report = build_report("alpine:3.20", [], {"version": "Trivy 0.test"})
    output = tmp_path / "secscan.html"

    write_html(report, output)

    assert "No vulnerabilities found." in output.read_text(encoding="utf-8")


def test_report_priority_opt_in_keeps_legacy_schema_unchanged(monkeypatch) -> None:
    monkeypatch.delenv("SECSCAN_KEV_CATALOG", raising=False)
    monkeypatch.delenv("SECSCAN_EPSS_CSV", raising=False)
    finding = Finding(
        vulnerability_id="CVE-2026-1234",
        package_name="example",
        installed_version="1.0",
        fixed_version=None,
        severity="CRITICAL",
        title="Example vulnerability",
        target="example",
        package_type="os",
        primary_url=None,
    )
    legacy = build_report("example", [finding], {"name": "test"})
    assert legacy["schema_version"] == "1.0"
    assert "priority" not in legacy["findings"][0]
    assert "priority" not in legacy["summary"]

    prioritized = build_report("example", [finding], {"name": "test"}, include_priority=True)
    assert prioritized["schema_version"] == "1.3"
    assert prioritized["findings"][0]["priority"]["tier"] == "high"
    assert prioritized["summary"]["priority"] == {
        "urgent": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "unassessed": 0,
    }
    assert prioritized["findings"][0]["priority"]["evidence"]["internet_exposure"] is None
    assert prioritized["findings"][0]["priority"]["evidence"]["known_exploited"] is None


def test_report_priority_marks_missing_severity_as_unassessed(monkeypatch) -> None:
    monkeypatch.delenv("SECSCAN_KEV_CATALOG", raising=False)
    monkeypatch.delenv("SECSCAN_EPSS_CSV", raising=False)
    finding = Finding(
        vulnerability_id="CVE-2026-9999",
        package_name="example",
        installed_version="1.0",
        fixed_version=None,
        severity="UNKNOWN",
        title="No severity",
        target="example",
        package_type=None,
        primary_url=None,
    )
    report = build_report("example", [finding], {"name": "test"}, include_priority=True)
    assert report["findings"][0]["priority"]["tier"] == "unassessed"
    assert report["summary"]["priority"]["unassessed"] == 1
