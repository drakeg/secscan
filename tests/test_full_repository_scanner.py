from __future__ import annotations

from secscan.scanners.full_repository import (
    FullRepositoryScanner,
    _checkov_findings,
    _gitleaks_findings,
    _semgrep_findings,
)
from secscan.scanners.registry import build_default_registry
from secscan.scanners.repository import RepositoryScanner


def test_repository_defaults_to_full_security_scan() -> None:
    registry = build_default_registry()

    assert isinstance(registry.get("repository"), FullRepositoryScanner)
    assert isinstance(registry.get("repository-trivy"), RepositoryScanner)
    assert registry.get("full-repository").capability.name == "full-repository"


def test_semgrep_findings_are_normalized_with_source_context() -> None:
    findings = _semgrep_findings(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected.eval-detected",
                    "path": "app/views.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Detected use of eval",
                        "severity": "ERROR",
                        "metadata": {"source": "https://semgrep.dev/r/example"},
                    },
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].package_type == "sast/semgrep"
    assert findings[0].target == "app/views.py:42"
    assert findings[0].title.startswith("[Semgrep]")


def test_gitleaks_findings_are_critical_and_do_not_store_secret_value() -> None:
    findings = _gitleaks_findings(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub Personal Access Token",
                "File": "config.env",
                "StartLine": 7,
                "Secret": "should-never-be-copied",
                "Match": "token=should-never-be-copied",
            }
        ]
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "CRITICAL"
    assert finding.package_type == "secret/gitleaks"
    assert "should-never-be-copied" not in str(finding.to_dict())


def test_checkov_findings_are_normalized() -> None:
    findings = _checkov_findings(
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 bucket allows public access",
                        "file_path": "/main.tf",
                        "file_line_range": [10, 14],
                        "resource": "aws_s3_bucket.example",
                        "guideline": "https://docs.prismacloud.io/example",
                    }
                ]
            },
        }
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "MEDIUM"
    assert finding.package_type == "iac/checkov/terraform"
    assert finding.target == "/main.tf:10"
    assert finding.title.startswith("[Checkov]")
