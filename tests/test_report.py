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
