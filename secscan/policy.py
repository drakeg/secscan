from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from secscan.models import Finding

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ROOT_KEYS = {"policy", "suppressions", "rules"}
POLICY_KEYS = {"fail_on"}
SUPPRESSION_KEYS = {"vulnerability", "package", "reason", "expires"}
RULE_KEYS = {
    "vulnerability",
    "package",
    "severity",
    "fix_available",
    "max_age_days",
    "fail_on",
    "reason",
}


@dataclass(frozen=True)
class Suppression:
    vulnerability_id: str
    reason: str
    expires: date
    package_name: str | None = None

    def matches(self, finding: Finding, today: date) -> bool:
        return (
            self.expires >= today
            and self.vulnerability_id == finding.vulnerability_id
            and (self.package_name is None or self.package_name == finding.package_name)
        )


@dataclass(frozen=True)
class PolicyRule:
    fail_on: str
    reason: str
    vulnerability_id: str | None = None
    package_name: str | None = None
    severity: str | None = None
    fix_available: bool | None = None
    max_age_days: int | None = None

    def matches(self, finding: Finding, today: date) -> bool:
        if self.vulnerability_id is not None and self.vulnerability_id != finding.vulnerability_id:
            return False
        if self.package_name is not None and self.package_name != finding.package_name:
            return False
        if self.severity is not None and self.severity != finding.severity:
            return False
        if self.fix_available is not None and self.fix_available != bool(finding.fixed_version):
            return False
        if self.max_age_days is not None:
            if finding.published_date is None:
                return False
            if (today - finding.published_date).days <= self.max_age_days:
                return False
        return SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK[self.fail_on]

    def signature(self) -> tuple[object, ...]:
        return (
            self.vulnerability_id,
            self.package_name,
            self.severity,
            self.fix_available,
            self.max_age_days,
        )


@dataclass(frozen=True)
class Policy:
    fail_on: str = "CRITICAL"
    suppressions: tuple[Suppression, ...] = ()
    rules: tuple[PolicyRule, ...] = ()


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str
    expires: date


@dataclass(frozen=True)
class RuleMatch:
    finding: Finding
    rule_index: int
    fail_on: str
    reason: str


@dataclass(frozen=True)
class PolicyEvaluation:
    active_findings: tuple[Finding, ...]
    suppressed_findings: tuple[SuppressedFinding, ...]
    rule_matches: tuple[RuleMatch, ...] = ()


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    return value


def _reject_unknown(data: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown keys: {', '.join(unknown)}")


def _severity(value: object, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    severity = str(value).upper()
    if severity != "NONE" and severity not in SEVERITY_RANK:
        raise ValueError(f"Unsupported severity threshold for {label}: {severity}")
    return severity


def _parse_suppression(value: object, index: int) -> Suppression:
    data = _require_mapping(value, f"suppression {index}")
    _reject_unknown(data, SUPPRESSION_KEYS, f"suppression {index}")
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
    return Suppression(vulnerability_id, reason, expires, package_name)


def _parse_rule(value: object, index: int) -> PolicyRule:
    data = _require_mapping(value, f"rule {index}")
    _reject_unknown(data, RULE_KEYS, f"rule {index}")
    fail_on = _severity(data.get("fail_on", "HIGH"), f"rule {index}")
    assert fail_on is not None
    reason = str(data.get("reason", f"policy rule {index} matched")).strip()
    severity = _severity(data.get("severity"), f"rule {index} severity", allow_none=True)
    max_age = data.get("max_age_days")
    if max_age is not None and (not isinstance(max_age, int) or max_age < 0):
        raise ValueError(f"rule {index} max_age_days must be a non-negative integer")
    fix_available = data.get("fix_available")
    if fix_available is not None and not isinstance(fix_available, bool):
        raise ValueError(f"rule {index} fix_available must be true or false")
    rule = PolicyRule(
        fail_on=fail_on,
        reason=reason,
        vulnerability_id=str(data["vulnerability"]).strip() if data.get("vulnerability") else None,
        package_name=str(data["package"]).strip() if data.get("package") else None,
        severity=severity,
        fix_available=fix_available,
        max_age_days=max_age,
    )
    if all(value is None for value in rule.signature()):
        raise ValueError(f"rule {index} requires at least one match condition")
    return rule


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read policy file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML policy file: {path}") from exc
    root = {} if raw is None else _require_mapping(raw, "policy file")
    _reject_unknown(root, ROOT_KEYS, "policy file")
    policy_data = _require_mapping(root.get("policy", {}), "policy")
    _reject_unknown(policy_data, POLICY_KEYS, "policy")
    fail_on = _severity(policy_data.get("fail_on", "CRITICAL"), "policy")
    assert fail_on is not None
    suppression_values = root.get("suppressions", [])
    rule_values = root.get("rules", [])
    if not isinstance(suppression_values, list):
        raise ValueError("suppressions must be a list")
    if not isinstance(rule_values, list):
        raise ValueError("rules must be a list")
    suppressions = tuple(_parse_suppression(value, index) for index, value in enumerate(suppression_values, 1))
    rules = tuple(_parse_rule(value, index) for index, value in enumerate(rule_values, 1))
    seen: dict[tuple[object, ...], PolicyRule] = {}
    for index, rule in enumerate(rules, 1):
        previous = seen.get(rule.signature())
        if previous is not None and previous.fail_on != rule.fail_on:
            raise ValueError(f"rule {index} conflicts with an earlier rule using the same match conditions")
        seen[rule.signature()] = rule
    return Policy(fail_on=fail_on, suppressions=suppressions, rules=rules)


def evaluate_policy(findings: list[Finding], policy: Policy, *, today: date | None = None) -> PolicyEvaluation:
    evaluation_date = today or date.today()
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    matches: list[RuleMatch] = []
    for finding in findings:
        suppression = next((item for item in policy.suppressions if item.matches(finding, evaluation_date)), None)
        if suppression is not None:
            suppressed.append(SuppressedFinding(finding, suppression.reason, suppression.expires))
            continue
        active.append(finding)
        for index, rule in enumerate(policy.rules, 1):
            if rule.matches(finding, evaluation_date):
                matches.append(RuleMatch(finding, index, rule.fail_on, rule.reason))
    return PolicyEvaluation(tuple(active), tuple(suppressed), tuple(matches))


def policy_failed(
    findings: list[Finding],
    fail_on: str,
    *,
    policy: Policy | None = None,
    today: date | None = None,
) -> bool:
    threshold = fail_on.upper()
    if threshold != "NONE" and threshold not in SEVERITY_RANK:
        raise ValueError(f"Unsupported severity threshold: {fail_on}")
    global_failure = threshold != "NONE" and any(
        SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK[threshold] for finding in findings
    )
    if global_failure:
        return True
    if policy is None:
        return False
    evaluation_date = today or date.today()
    return any(rule.matches(finding, evaluation_date) for finding in findings for rule in policy.rules)
