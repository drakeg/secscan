from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from secscan.cli import main
from secscan.github_issues import (
    GITHUB_API_VERSION,
    GitHubIssueError,
    build_github_issue_export,
    submit_github_issue,
    validate_repository,
)


def _report(path: Path, *, findings: int = 2) -> Path:
    items = [
        {
            "vulnerability_id": f"CVE-2026-{index:04d}",
            "package_name": f"package-{index}",
            "installed_version": "1.0",
            "fixed_version": "1.1" if index % 2 else None,
            "severity": "HIGH" if index % 2 else "CRITICAL",
            "title": "Example",
            "target": "alpine:3.20",
            "package_type": "apk",
            "primary_url": None,
        }
        for index in range(findings)
    ]
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.2",
                "target": {"type": "container_image", "name": "alpine:3.20"},
                "summary": {
                    "CRITICAL": sum(item["severity"] == "CRITICAL" for item in items),
                    "HIGH": sum(item["severity"] == "HIGH" for item in items),
                    "MEDIUM": 0,
                    "LOW": 0,
                    "UNKNOWN": 0,
                    "total": len(items),
                },
                "findings": items,
            }
        ),
        encoding="utf-8",
    )
    return path


class _Response:
    def __init__(self, document: object) -> None:
        self.payload = json.dumps(document).encode()

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


def test_build_export_is_bounded_and_deterministic(tmp_path: Path) -> None:
    document = build_github_issue_export(_report(tmp_path / "secscan.json", findings=52), "acme/security")

    request = document["request"]
    assert isinstance(request, dict)
    assert request["title"] == "[secscan] alpine:3.20: 26 critical, 26 high"
    assert str(request["body"]).count("| CRITICAL |") == 26
    assert str(request["body"]).count("| HIGH |") == 24
    assert "Showing the first 50; 2 findings omitted" in str(request["body"])
    assert document["submission"] is None


@pytest.mark.parametrize(
    "repository",
    ["owner", "/repo", "owner/", "owner/repo/extra", "owner/../repo", "https://github.com/a/b"],
)
def test_repository_validation_rejects_non_exact_destinations(repository: str) -> None:
    with pytest.raises(ValueError, match="OWNER/REPOSITORY"):
        validate_repository(repository)


def test_report_validation_fails_closed(tmp_path: Path) -> None:
    report = tmp_path / "secscan.json"
    report.write_text('{"schema_version":"9.0"}', encoding="utf-8")

    with pytest.raises(ValueError, match="schema_version"):
        build_github_issue_export(report, "acme/security")


def test_report_summary_must_match_findings(tmp_path: Path) -> None:
    report = _report(tmp_path / "secscan.json")
    document = json.loads(report.read_text(encoding="utf-8"))
    document["summary"]["CRITICAL"] = 99
    report.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        build_github_issue_export(report, "acme/security")


def test_submit_uses_fixed_github_origin_and_required_headers(tmp_path: Path) -> None:
    export = build_github_issue_export(_report(tmp_path / "secscan.json"), "acme/security")
    captured: dict[str, Any] = {}

    def opener(request: Request, *, timeout: int) -> _Response:
        captured.update(request=request, timeout=timeout)
        return _Response({"number": 42, "html_url": "https://github.com/acme/security/issues/42"})

    completed = submit_github_issue(export, "secret-token", opener=opener)

    request = captured["request"]
    assert isinstance(request, Request)
    assert request.full_url == "https://api.github.com/repos/acme/security/issues"
    assert request.method == "POST"
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("X-github-api-version") == GITHUB_API_VERSION
    assert captured["timeout"] == 30
    assert json.loads(request.data or b"{}") == export["request"]
    assert completed["submission"] == {
        "number": 42,
        "url": "https://github.com/acme/security/issues/42",
    }


def test_submit_reports_http_status_without_leaking_response_or_token(tmp_path: Path) -> None:
    export = build_github_issue_export(_report(tmp_path / "secscan.json"), "acme/security")

    def opener(_request: Request, *, timeout: int) -> _Response:
        assert timeout == 30
        raise HTTPError("https://api.github.com", 403, "secret response", {}, None)

    with pytest.raises(GitHubIssueError, match="HTTP 403") as error:
        submit_github_issue(export, "super-secret", opener=opener)
    assert "super-secret" not in str(error.value)
    assert "secret response" not in str(error.value)


def test_submit_rejects_response_for_another_repository(tmp_path: Path) -> None:
    export = build_github_issue_export(_report(tmp_path / "secscan.json"), "acme/security")

    def opener(_request: Request, *, timeout: int) -> _Response:
        assert timeout == 30
        return _Response({"number": 42, "html_url": "https://github.com/other/repo/issues/42"})

    with pytest.raises(GitHubIssueError, match="valid issue URL"):
        submit_github_issue(export, "secret-token", opener=opener)


def test_cli_defaults_to_local_export_without_token(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "github-issue.json"

    exit_code = main(
        [
            "export",
            "github-issue",
            str(_report(tmp_path / "secscan.json")),
            "--repository",
            "acme/security",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["submission"] is None
    assert "no network request" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_cli_submit_requires_server_side_token(tmp_path: Path, capsys: object) -> None:
    exit_code = main(
        [
            "export",
            "github-issue",
            str(_report(tmp_path / "secscan.json")),
            "--repository",
            "acme/security",
            "--submit",
            "--output",
            str(tmp_path / "out.json"),
        ]
    )

    assert exit_code == 1
    assert "SECSCAN_GITHUB_ISSUES_TOKEN" in capsys.readouterr().err  # type: ignore[attr-defined]
