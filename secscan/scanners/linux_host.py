from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote

from secscan.models import Finding
from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.scanners.network import validate_network_target
from secscan.trivy import scan_sbom


_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
_ALLOWED_FIREWALL_STATES = {"active", "inactive", "unknown", "unavailable"}
_PACKAGE_PREFIX = "package"
_TRIVY_OS_TYPES: dict[str, tuple[str, str, str]] = {
    "ubuntu": ("deb", "ubuntu", "ubuntu"),
    "debian": ("deb", "debian", "debian"),
    "rhel": ("rpm", "redhat", "redhat"),
    "centos": ("rpm", "centos", "centos"),
    "rocky": ("rpm", "rocky", "rocky"),
    "almalinux": ("rpm", "alma", "alma"),
    "fedora": ("rpm", "fedora", "fedora"),
    "amzn": ("rpm", "amazon", "amazon"),
    "ol": ("rpm", "oracle", "oracle"),
    "opensuse-leap": ("rpm", "opensuse", "opensuse"),
}

_REMOTE_SCRIPT = r"""set -eu
emit() { printf '%s\t%s\n' "$1" "$2"; }
emit os_kernel "$(uname -s 2>/dev/null || true)"
emit kernel_release "$(uname -r 2>/dev/null || true)"
if [ -r /etc/os-release ]; then
  os_id=$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '\"')
  os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '\"')
else
  os_id=""
  os_version=""
fi
emit os_id "$os_id"
emit os_version "$os_version"
uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//' || true)
emit uid0_accounts "$uid0"
if command -v sshd >/dev/null 2>&1; then
  sshd_config=$(sshd -T 2>/dev/null || true)
  password_auth=$(printf '%s\n' "$sshd_config" | awk '$1 == "passwordauthentication" {print $2; exit}')
  root_login=$(printf '%s\n' "$sshd_config" | awk '$1 == "permitrootlogin" {print $2; exit}')
  emit ssh_password_auth "${password_auth:-unknown}"
  emit ssh_root_login "${root_login:-unknown}"
else
  emit ssh_password_auth unavailable
  emit ssh_root_login unavailable
fi
if command -v apt >/dev/null 2>&1; then
  pending=$(apt list --upgradable 2>/dev/null | awk 'NR > 1 && NF {count++} END {print count+0}')
  emit pending_updates "$pending"
else
  emit pending_updates unavailable
fi
firewall=unavailable
if command -v ufw >/dev/null 2>&1; then
  status=$(ufw status 2>/dev/null | awk -F: '/^Status:/ {gsub(/^[ \t]+/, "", $2); print tolower($2); exit}' || true)
  [ -n "$status" ] && firewall="$status"
elif command -v firewall-cmd >/dev/null 2>&1; then
  status=$(firewall-cmd --state 2>/dev/null || true)
  case "$status" in running) firewall=active ;; not\ running) firewall=inactive ;; *) firewall=unknown ;; esac
fi
emit firewall_state "$firewall"
world_writable=$(find /etc -xdev -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | head -n 20 | tr '\n' ',' | sed 's/,$//' || true)
emit world_writable_etc "$world_writable"
if command -v dpkg-query >/dev/null 2>&1; then
  emit package_manager dpkg
  dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' 2>/dev/null | sed 's/^/package\t/'
elif command -v rpm >/dev/null 2>&1; then
  emit package_manager rpm
  rpm -qa --qf 'package\t%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null
else
  emit package_manager unavailable
fi
"""


def validate_ssh_user(user: str) -> str:
    value = user.strip()
    if not _USER_RE.fullmatch(value):
        raise ValueError("SSH user must be a simple Linux username")
    return value


def _setting(request: ScanRequest, name: str) -> str | None:
    if request.environment and request.environment.get(name):
        return request.environment[name]
    return os.environ.get(name)


def _required_setting(request: ScanRequest, name: str) -> str:
    value = _setting(request, name)
    if not value:
        raise ValueError(f"{name} is required for linux-host scans")
    return value


def _required_file(request: ScanRequest, name: str) -> Path:
    path = Path(_required_setting(request, name)).expanduser()
    if not path.is_absolute() or not path.is_file():
        raise ValueError(f"{name} must point to an existing absolute file")
    return path


def _ssh_port(request: ScanRequest) -> int:
    raw = _setting(request, "SECSCAN_SSH_PORT") or "22"
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError("SECSCAN_SSH_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SECSCAN_SSH_PORT must be between 1 and 65535")
    return port


def _parse_output(output: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    values: dict[str, str] = {}
    packages: dict[tuple[str, str, str], dict[str, str]] = {}
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        if fields[0] == _PACKAGE_PREFIX:
            if len(fields) != 4 or not all(fields[1:]):
                raise ValueError("Linux host assessment returned malformed package inventory")
            name, version, architecture = (value.strip() for value in fields[1:])
            package_key = (name, version, architecture)
            packages[package_key] = {
                "name": name,
                "version": version,
                "architecture": architecture,
            }
            continue
        output_key, separator, value = raw_line.partition("\t")
        if separator != "\t" or not output_key or output_key in values:
            raise ValueError("Linux host assessment returned malformed output")
        values[output_key] = value.strip()
    required = {
        "os_kernel",
        "kernel_release",
        "os_id",
        "os_version",
        "uid0_accounts",
        "ssh_password_auth",
        "ssh_root_login",
        "pending_updates",
        "firewall_state",
        "world_writable_etc",
        "package_manager",
    }
    if not required.issubset(values):
        raise ValueError("Linux host assessment returned incomplete output")
    package_manager = values["package_manager"]
    if package_manager not in {"dpkg", "rpm", "unavailable"}:
        raise ValueError("Linux host assessment returned an invalid package manager")
    normalized = [
        packages[package_key] | {"source": package_manager}
        for package_key in sorted(packages)
    ]
    if package_manager == "unavailable" and normalized:
        raise ValueError("Linux host assessment returned packages without a supported package manager")
    return values, normalized


def _trivy_os_metadata(values: dict[str, str]) -> tuple[str, str, str] | None:
    os_id = values["os_id"].lower()
    metadata = _TRIVY_OS_TYPES.get(os_id)
    if metadata is None:
        return None
    expected_manager = "dpkg" if metadata[0] == "deb" else "rpm"
    if values["package_manager"] != expected_manager:
        return None
    if not values["os_version"]:
        return None
    return metadata


def _purl_component(
    package: dict[str, str], values: dict[str, str], metadata: tuple[str, str, str]
) -> dict[str, object]:
    purl_type, namespace, pkg_type = metadata
    name = package["name"]
    version = package["version"]
    architecture = package["architecture"]
    distro = f"{values['os_id'].lower()}-{values['os_version']}"
    purl = (
        f"pkg:{purl_type}/{quote(namespace, safe='')}/{quote(name, safe='.-_~')}"
        f"@{quote(version, safe='.:_-~')}?arch={quote(architecture, safe='.-_~')}"
        f"&distro={quote(distro, safe='.-_~')}"
    )
    return {
        "bom-ref": purl,
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [
            {"name": "aquasecurity:trivy:PkgID", "value": f"{name}@{version}"},
            {"name": "aquasecurity:trivy:PkgType", "value": pkg_type},
        ],
    }


def _build_trivy_sbom(
    values: dict[str, str], packages: list[dict[str, str]], target: str
) -> dict[str, object] | None:
    metadata = _trivy_os_metadata(values)
    if metadata is None:
        return None
    components = [_purl_component(package, values, metadata) for package in packages]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "device",
                "name": target,
                "version": values["os_version"],
            }
        },
        "components": components,
    }


def _package_vulnerabilities(
    values: dict[str, str], packages: list[dict[str, str]], target: str, timeout_seconds: int
) -> tuple[tuple[Finding, ...], dict[str, object]]:
    if not packages:
        return (), {"status": "no_packages", "finding_count": 0}
    sbom = _build_trivy_sbom(values, packages, target)
    if sbom is None:
        return (), {
            "status": "unsupported_distro",
            "finding_count": 0,
            "os_id": values["os_id"],
            "os_version": values["os_version"],
        }
    with tempfile.TemporaryDirectory(prefix="secscan-linux-sbom-") as temp_dir:
        sbom_path = Path(temp_dir) / "linux-host.cdx.json"
        sbom_path.write_text(json.dumps(sbom, sort_keys=True) + "\n", encoding="utf-8")
        raw = scan_sbom(sbom_path, timeout_seconds=timeout_seconds)
    normalized = tuple(
        replace(
            finding,
            target=target,
            package_type=f"linux-host/{finding.package_type or 'os'}",
        )
        for finding in normalize_trivy(raw)
    )
    return normalized, {
        "status": "completed",
        "finding_count": len(normalized),
        "engine": "trivy-sbom",
    }


def _findings(values: dict[str, str], target: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    pending = values["pending_updates"]
    if pending != "unavailable":
        try:
            pending_count = int(pending)
        except ValueError as exc:
            raise ValueError("Linux host assessment returned an invalid pending update count") from exc
        if pending_count > 0:
            findings.append(
                Finding(
                    vulnerability_id="LINUX-UPDATES-PENDING",
                    package_name="operating-system",
                    installed_version=f"{pending_count} pending package updates",
                    fixed_version="apply reviewed package updates",
                    severity="MEDIUM",
                    title=f"[Linux host] {pending_count} package updates are pending",
                    target=target,
                    package_type="linux-host/posture",
                    primary_url=None,
                )
            )
    if values["ssh_password_auth"].lower() == "yes":
        findings.append(
            Finding(
                vulnerability_id="SSH-PASSWORD-AUTH-ENABLED",
                package_name="openssh-server",
                installed_version="PasswordAuthentication yes",
                fixed_version="PasswordAuthentication no",
                severity="HIGH",
                title="[Linux host] SSH password authentication is enabled",
                target=target,
                package_type="linux-host/ssh",
                primary_url=None,
            )
        )
    if values["ssh_root_login"].lower() == "yes":
        findings.append(
            Finding(
                vulnerability_id="SSH-ROOT-LOGIN-ENABLED",
                package_name="openssh-server",
                installed_version="PermitRootLogin yes",
                fixed_version="PermitRootLogin no or prohibit-password",
                severity="HIGH",
                title="[Linux host] Direct SSH root login is permitted",
                target=target,
                package_type="linux-host/ssh",
                primary_url=None,
            )
        )
    uid0_accounts = [value for value in values["uid0_accounts"].split(",") if value]
    unexpected_uid0 = [value for value in uid0_accounts if value != "root"]
    if unexpected_uid0:
        findings.append(
            Finding(
                vulnerability_id="LINUX-EXTRA-UID0-ACCOUNTS",
                package_name="local-accounts",
                installed_version=", ".join(unexpected_uid0),
                fixed_version="remove unnecessary UID 0 accounts",
                severity="CRITICAL",
                title="[Linux host] Additional UID 0 accounts were found",
                target=target,
                package_type="linux-host/accounts",
                primary_url=None,
            )
        )
    firewall_state = values["firewall_state"].lower()
    if firewall_state not in _ALLOWED_FIREWALL_STATES:
        firewall_state = "unknown"
    if firewall_state == "inactive":
        findings.append(
            Finding(
                vulnerability_id="LINUX-HOST-FIREWALL-INACTIVE",
                package_name="host-firewall",
                installed_version="inactive",
                fixed_version="enable and configure an appropriate host firewall",
                severity="MEDIUM",
                title="[Linux host] Host firewall is inactive",
                target=target,
                package_type="linux-host/firewall",
                primary_url=None,
            )
        )
    world_writable = [value for value in values["world_writable_etc"].split(",") if value]
    if world_writable:
        findings.append(
            Finding(
                vulnerability_id="LINUX-WORLD-WRITABLE-ETC-FILES",
                package_name="filesystem-permissions",
                installed_version=", ".join(world_writable),
                fixed_version="remove world-write permission from sensitive configuration files",
                severity="HIGH",
                title="[Linux host] World-writable files were found under /etc",
                target=target,
                package_type="linux-host/filesystem",
                primary_url=None,
            )
        )
    return tuple(findings)


class LinuxHostScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="linux-host",
            description="authenticated Linux host posture, package inventory, and package CVE assessment over key-based SSH",
            target_help="single Linux hostname or IP address",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target = validate_network_target(request.target)
        user = validate_ssh_user(_required_setting(request, "SECSCAN_SSH_USER"))
        key_path = _required_file(request, "SECSCAN_SSH_KEY")
        known_hosts = _required_file(request, "SECSCAN_SSH_KNOWN_HOSTS")
        port = _ssh_port(request)
        command = [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(port),
            "-i",
            str(key_path),
            f"{user}@{target}",
            "--",
            "sh",
            "-s",
        ]
        try:
            completed = subprocess.run(
                command,
                input=_REMOTE_SCRIPT,
                text=True,
                capture_output=True,
                check=False,
                timeout=request.timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise ValueError("OpenSSH client is required for linux-host assessments") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("Linux host assessment timed out") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            message = detail[-1] if detail else f"exit code {completed.returncode}"
            raise ValueError(f"Linux host SSH assessment failed: {message}")
        values, packages = _parse_output(completed.stdout)
        if values["os_kernel"].lower() != "linux":
            raise ValueError("linux-host target did not report a Linux kernel")
        posture_findings = _findings(values, target)
        vulnerability_findings, vulnerability_scan = _package_vulnerabilities(
            values, packages, target, request.timeout_seconds
        )
        findings = posture_findings + vulnerability_findings
        return ScanResult(
            request=request,
            findings=findings,
            raw={
                "schema_version": 3,
                "target": target,
                "host": {
                    "os_kernel": values["os_kernel"],
                    "kernel_release": values["kernel_release"],
                    "os_id": values["os_id"],
                    "os_version": values["os_version"],
                },
                "checks": {
                    "pending_updates": values["pending_updates"],
                    "ssh_password_auth": values["ssh_password_auth"],
                    "ssh_root_login": values["ssh_root_login"],
                    "firewall_state": values["firewall_state"],
                    "uid0_accounts": values["uid0_accounts"],
                    "world_writable_etc": values["world_writable_etc"],
                },
                "package_inventory": {
                    "manager": values["package_manager"],
                    "count": len(packages),
                    "packages": packages,
                },
                "package_vulnerability_scan": vulnerability_scan,
            },
            scanner={"name": "secscan-linux-host", "version": "ssh-posture-packages-cves-v3"},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {"component": {"type": "device", "name": request.target}},
                    "components": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
