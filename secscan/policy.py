from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from secscan.models import Finding

SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class Suppression:
    vulnerability_id: str
    reason: str
    expires: date
    package_name: str | None = None

    def matches(self, finding: Finding, today: date) -> bool:
        if self.expires < today:
            return False
        if self.vulnerability_id != finding.vulnerability_id:
            return False
        return self.package_name is None or self.package_name == finding.package_name


@dataclass(frozen=True)
class Policy:
    fail_on: str = "CRITICAL"
    suppressions: tuple[Suppression, ...] = ()


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str
    expires: date


@dataclass(frozen=True)
class PolicyEvaluation:
    active_findings: tuple[Finding, ...]
    suppressed_findings: tuple[SuppressedFinding, ...]


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    return value


def _parse_suppression(value: object, index: int) -> Suppression:
    data = _require_mapping(value, f"suppression {index}")
    vulnerability_id = str(data.get("vulnerability", "")).strip()
    reason = str(data.get("reason", "")).strip()
    expires_value = data.get("expires")
    package_name = str(data["package"]).strip() if data.get("package") else None

    if not vulnerability_id:
        raise ValueError(f"suppression {index} requires vulnerability")
    if not reason:
        raise ValueError(f"suppression {index} requires reason")
    if expires_value is None:
        raise ValueError(f"suppression {index} requires expires")

    try:
        expires = expires_value if isinstance(expires_value, date) else date.fromisoformat(str(expires_value))
    except ValueError as exc:
        raise ValueError(f"suppression {index} expires must use YYYY-MM-DD") from exc

    return Suppression(
        vulnerability_id=vulnerability_id,
        package_name=package_name,
        reason=reason,
        expires=expires,
    )


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read policy file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML policy file: {path}") from exc

    root = {} if raw is None else _require_mapping(raw, "policy file")
    policy_data = _require_mapping(root.get("policy", {}), "policy")
    fail_on = str(policy_data.get("fail_on", "CRITICAL")).upper()
    if fail_on != "NONE" and fail_on not in SEVERITY_RANK:
        raise ValueError(f"Unsupported severity threshold: {fail_on}")

    suppression_values = root.get("suppressions", [])
    if not isinstance(suppression_values, list):
        raise ValueError("suppressions must be a list")
    suppressions = tuple(
        _parse_suppression(value, index)
        for index, value in enumerate(suppression_values, start=1)
    )
    return Policy(fail_on=fail_on, suppressions=suppressions)


def evaluate_policy(
    findings: list[Finding],
    policy: Policy,
    *,
    today: date | None = None,
) -> PolicyEvaluation:
    evaluation_date = today or date.today()
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []

    for finding in findings:
        matching = next(
            (
                suppression
                for suppression in policy.suppressions
                if suppression.matches(finding, evaluation_date)
            ),
            None,
        )
        if matching is None:
            active.append(finding)
        else:
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    reason=matching.reason,
                    expires=matching.expires,
                )
            )

    return PolicyEvaluation(tuple(active), tuple(suppressed))


def policy_failed(findings: list[Finding], fail_on: str) -> bool:
    threshold = fail_on.upper()
    if threshold == "NONE":
        return False
    if threshold not in SEVERITY_RANK:
        raise ValueError(f"Unsupported severity threshold: {fail_on}")
    minimum = SEVERITY_RANK[threshold]
    return any(SEVERITY_RANK.get(finding.severity, 0) >= minimum for finding in findings)
