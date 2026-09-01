from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

GITHUB_API_VERSION = "2026-03-10"
MAX_FINDINGS = 50
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class GitHubIssueError(RuntimeError):
    pass


def validate_repository(value: str) -> str:
    repository = value.strip()
    if not _REPOSITORY.fullmatch(repository) or ".." in repository:
        raise ValueError("GitHub repository must use the exact OWNER/REPOSITORY form")
    return repository


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"secscan report {field} must be a non-empty string")
    return value.strip()


def _count(summary: dict[str, Any], severity: str) -> int:
    value = summary.get(severity, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"secscan report summary {severity} must be a non-negative integer")
    return value


def _markdown(value: object) -> str:
    return str(value or "—").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def build_github_issue_export(report_path: Path, repository: str) -> dict[str, object]:
    repository = validate_repository(repository)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("secscan report is not readable valid JSON") from exc
    if not isinstance(report, dict):
        raise ValueError("secscan report root must be an object")
    if report.get("schema_version") not in {"1.0", "1.1", "1.2"}:
        raise ValueError("secscan report schema_version is not supported")
    target = report.get("target")
    summary = report.get("summary")
    findings = report.get("findings")
    if not isinstance(target, dict) or not isinstance(summary, dict) or not isinstance(findings, list):
        raise ValueError("secscan report requires target, summary, and findings")
    target_name = _text(target.get("name"), "target name")
    target_type = _text(target.get("type"), "target type")
    counts = {severity: _count(summary, severity) for severity in _SEVERITY_ORDER}

    normalized: list[dict[str, str]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError(f"secscan report finding {index} must be an object")
        severity = _text(finding.get("severity"), f"finding {index} severity").upper()
        if severity not in _SEVERITY_ORDER:
            raise ValueError(f"secscan report finding {index} severity is not supported")
        normalized.append(
            {
                "severity": severity,
                "vulnerability_id": _text(finding.get("vulnerability_id"), f"finding {index} vulnerability_id"),
                "package_name": _text(finding.get("package_name"), f"finding {index} package_name"),
                "fixed_version": str(finding.get("fixed_version") or "No fix listed"),
                "target": str(finding.get("target") or target_name),
            }
        )
    normalized.sort(
        key=lambda item: (
            _SEVERITY_ORDER[item["severity"]],
            item["vulnerability_id"],
            item["package_name"],
            item["target"],
        )
    )
    actual_counts = {severity: sum(item["severity"] == severity for item in normalized) for severity in _SEVERITY_ORDER}
    if counts != actual_counts:
        raise ValueError("secscan report severity summary does not match its findings")
    displayed = normalized[:MAX_FINDINGS]
    title = f"[secscan] {target_name}: {counts['CRITICAL']} critical, {counts['HIGH']} high"
    if len(title) > 200:
        title = title[:197] + "..."
    rows = [
        "| Severity | Vulnerability | Package | Fixed version | Finding target |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows.extend("| " + " | ".join(_markdown(item[field]) for field in item) + " |" for item in displayed)
    if not displayed:
        rows.append("| — | No active findings | — | — | — |")
    omitted = len(normalized) - len(displayed)
    body_parts = [
        "## secscan vulnerability summary",
        "",
        f"- Target type: {_markdown(target_type)}",
        f"- Target: {_markdown(target_name)}",
        f"- Findings: {len(normalized)}",
        "- Severity: " + ", ".join(f"{key}={counts[key]}" for key in _SEVERITY_ORDER),
        "",
        *rows,
    ]
    if omitted:
        body_parts.extend(["", f"_Showing the first {MAX_FINDINGS}; {omitted} findings omitted._"])
    body_parts.extend(["", "Generated from a local secscan report. Verify current status before remediation."])
    return {
        "schema_version": 1,
        "provider": "github_issues",
        "repository": repository,
        "request": {"title": title, "body": "\n".join(body_parts)},
        "submission": None,
    }


def submit_github_issue(
    export: dict[str, object],
    token: str,
    *,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, object]:
    secret = token.strip()
    if not secret or "\n" in secret or "\r" in secret:
        raise ValueError("SECSCAN_GITHUB_ISSUES_TOKEN must be a non-empty single-line token")
    repository = validate_repository(str(export.get("repository", "")))
    payload = export.get("request")
    if not isinstance(payload, dict):
        raise ValueError("GitHub issue export request must be an object")
    request = Request(
        f"https://api.github.com/repos/{repository}/issues",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "User-Agent": "secscan-github-issues",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
        method="POST",
    )
    try:
        with opener(request, timeout=30) as response:
            document = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise GitHubIssueError(f"GitHub issue creation failed with HTTP {exc.code}") from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise GitHubIssueError("GitHub issue creation request failed") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubIssueError("GitHub issue creation returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise GitHubIssueError("GitHub issue creation returned an invalid response")
    number = document.get("number")
    html_url = document.get("html_url")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GitHubIssueError("GitHub issue creation response has no valid issue number")
    expected_url_prefix = f"https://github.com/{repository}/issues/"
    if not isinstance(html_url, str) or not html_url.startswith(expected_url_prefix):
        raise GitHubIssueError("GitHub issue creation response has no valid issue URL")
    completed = dict(export)
    completed["submission"] = {"number": number, "url": html_url}
    return completed
