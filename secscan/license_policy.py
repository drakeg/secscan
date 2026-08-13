from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secscan.sbom_inventory_compare import load_sbom_inventory

ROOT_KEYS = {"license_policy"}
POLICY_KEYS = {"allow", "deny", "require_declared"}


@dataclass(frozen=True)
class LicensePolicy:
    allow: tuple[str, ...] | None = None
    deny: tuple[str, ...] = ()
    require_declared: bool = False


def _reject_unknown(data: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown keys: {', '.join(unknown)}")


def _license_values(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    values: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{label} item {index} must be a non-empty string")
        values.append(item.strip())
    if len(values) != len(set(values)):
        raise ValueError(f"{label} contains duplicate values")
    return tuple(sorted(values))


def load_license_policy(path: Path) -> LicensePolicy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read license policy file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML license policy file: {path}") from exc
    if not isinstance(raw, dict):
        raise ValueError("license policy file must be a mapping")
    _reject_unknown(raw, ROOT_KEYS, "license policy file")
    data = raw.get("license_policy")
    if not isinstance(data, dict):
        raise ValueError("license_policy must be a mapping")
    _reject_unknown(data, POLICY_KEYS, "license_policy")
    allow = _license_values(data["allow"], "license_policy.allow") if "allow" in data else None
    deny = _license_values(data.get("deny", []), "license_policy.deny")
    require_declared = data.get("require_declared", False)
    if not isinstance(require_declared, bool):
        raise ValueError("license_policy.require_declared must be true or false")
    overlap = sorted(set(allow or ()) & set(deny))
    if overlap:
        raise ValueError(f"license policy values cannot be both allowed and denied: {', '.join(overlap)}")
    return LicensePolicy(allow=allow, deny=deny, require_declared=require_declared)


def evaluate_license_policy(inventory: Path, policy: LicensePolicy) -> dict[str, object]:
    inventory_path = inventory.expanduser().resolve()
    packages = load_sbom_inventory(inventory_path)
    violations: list[dict[str, object]] = []
    allow = set(policy.allow) if policy.allow is not None else None
    deny = set(policy.deny)
    for identity in sorted(packages):
        package = packages[identity]
        licenses = package["declared_licenses"]
        reasons: list[str] = []
        if policy.require_declared and not licenses:
            reasons.append("declared license is required")
        for value in licenses:
            if value in deny:
                reasons.append(f"declared license is denied: {value}")
            elif allow is not None and value not in allow:
                reasons.append(f"declared license is not allowed: {value}")
        if reasons:
            violations.append({"package": package, "reasons": reasons})
    return {
        "schema_version": 1,
        "inventory": str(inventory_path),
        "policy": {
            "allow": list(policy.allow) if policy.allow is not None else None,
            "deny": list(policy.deny),
            "require_declared": policy.require_declared,
        },
        "summary": {
            "package_count": len(packages),
            "violation_count": len(violations),
            "passed": not violations,
        },
        "violations": violations,
    }
