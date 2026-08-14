from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from secscan.sbom_inventory import InventoryPackage
from secscan.sbom_inventory_compare import load_sbom_inventory

ROOT_KEYS = {"license_policy"}
POLICY_KEYS = {"allow", "deny", "require_declared", "exceptions"}
EXCEPTION_KEYS = {"package", "license", "reason", "expires"}
PACKAGE_KEYS = {"purl", "name", "version"}


@dataclass(frozen=True)
class LicenseException:
    license: str
    reason: str
    expires: date
    purl: str | None = None
    name: str | None = None
    version: str | None = None

    def matches(self, package: InventoryPackage, license_value: str, today: date) -> bool:
        if self.expires < today or self.license != license_value:
            return False
        if self.purl is not None:
            return package["purl"] == self.purl
        return (
            package["purl"] is None
            and package["name"] == self.name
            and package["version"] == self.version
        )

    def document(self) -> dict[str, object]:
        package: dict[str, object]
        if self.purl is not None:
            package = {"purl": self.purl}
        else:
            package = {"name": self.name, "version": self.version}
        return {
            "package": package,
            "license": self.license,
            "reason": self.reason,
            "expires": self.expires.isoformat(),
        }


@dataclass(frozen=True)
class LicensePolicy:
    allow: tuple[str, ...] | None = None
    deny: tuple[str, ...] = ()
    require_declared: bool = False
    exceptions: tuple[LicenseException, ...] = ()


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


def _required_string(data: dict[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} requires {key}")
    return value.strip()


def _parse_exception(value: object, index: int) -> LicenseException:
    label = f"license_policy exception {index}"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    _reject_unknown(value, EXCEPTION_KEYS, label)
    package = value.get("package")
    if not isinstance(package, dict):
        raise ValueError(f"{label} package must be a mapping")
    _reject_unknown(package, PACKAGE_KEYS, f"{label} package")
    purl = package.get("purl")
    name = package.get("name")
    if purl is not None:
        if not isinstance(purl, str) or not purl.strip():
            raise ValueError(f"{label} package purl must be a non-empty string")
        if "name" in package or "version" in package:
            raise ValueError(f"{label} package must use purl or name and version")
        purl = purl.strip()
        version = None
    else:
        if not isinstance(name, str) or not name.strip() or "version" not in package:
            raise ValueError(f"{label} package requires purl or name and version")
        name = name.strip()
        version = package["version"]
        if version is not None and (not isinstance(version, str) or not version.strip()):
            raise ValueError(f"{label} package version must be a non-empty string or null")
        version = version.strip() if isinstance(version, str) else None
    expires_value = value.get("expires")
    if expires_value is None:
        raise ValueError(f"{label} requires expires")
    try:
        expires = (
            expires_value
            if isinstance(expires_value, date)
            else date.fromisoformat(str(expires_value))
        )
    except ValueError as exc:
        raise ValueError(f"{label} expires must use YYYY-MM-DD") from exc
    return LicenseException(
        license=_required_string(value, "license", label),
        reason=_required_string(value, "reason", label),
        expires=expires,
        purl=purl,
        name=name,
        version=version,
    )


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
    raw_exceptions = data.get("exceptions", [])
    if not isinstance(raw_exceptions, list):
        raise ValueError("license_policy.exceptions must be a list")
    exceptions = tuple(_parse_exception(value, index) for index, value in enumerate(raw_exceptions))
    signatures = [
        (exception.purl, exception.name, exception.version, exception.license)
        for exception in exceptions
    ]
    if len(signatures) != len(set(signatures)):
        raise ValueError("license_policy.exceptions contains duplicate package and license matches")
    return LicensePolicy(
        allow=allow,
        deny=deny,
        require_declared=require_declared,
        exceptions=exceptions,
    )


def evaluate_license_policy(
    inventory: Path, policy: LicensePolicy, *, today: date | None = None
) -> dict[str, object]:
    evaluation_date = today or date.today()
    inventory_path = inventory.expanduser().resolve()
    packages = load_sbom_inventory(inventory_path)
    violations: list[dict[str, object]] = []
    suppressed: list[dict[str, object]] = []
    allow = set(policy.allow) if policy.allow is not None else None
    deny = set(policy.deny)
    for identity in sorted(packages):
        package = packages[identity]
        licenses = package["declared_licenses"]
        reasons: list[str] = []
        if policy.require_declared and not licenses:
            reasons.append("declared license is required")
        for value in licenses:
            reason: str | None = None
            if value in deny:
                reason = f"declared license is denied: {value}"
            elif allow is not None and value not in allow:
                reason = f"declared license is not allowed: {value}"
            if reason is None:
                continue
            exception = next(
                (
                    exception
                    for exception in policy.exceptions
                    if exception.matches(package, value, evaluation_date)
                ),
                None,
            )
            if exception is None:
                reasons.append(reason)
            else:
                suppressed.append(
                    {
                        "package": package,
                        "license": value,
                        "violation": reason,
                        "reason": exception.reason,
                        "expires": exception.expires.isoformat(),
                    }
                )
        if reasons:
            violations.append({"package": package, "reasons": reasons})
    return {
        "schema_version": 1,
        "inventory": str(inventory_path),
        "policy": {
            "allow": list(policy.allow) if policy.allow is not None else None,
            "deny": list(policy.deny),
            "require_declared": policy.require_declared,
            "exceptions": [exception.document() for exception in policy.exceptions],
        },
        "summary": {
            "package_count": len(packages),
            "violation_count": len(violations),
            "suppressed_count": len(suppressed),
            "passed": not violations,
        },
        "violations": violations,
        "suppressed": suppressed,
    }
