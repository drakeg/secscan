from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

from secscan.models import Finding
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.scanners.network import validate_network_target


_WINDOWS_USER_RE = re.compile(r"^[A-Za-z0-9_.\\-]{1,128}$")
_SOFTWARE_PREFIX = "software"
_ALLOWED_FIREWALL_STATES = {"enabled", "disabled", "unavailable"}
_ALLOWED_BOOLEAN_STATES = {"true", "false", "unavailable"}

_REMOTE_SCRIPT = r"""$ErrorActionPreference = 'Stop'
function Emit([string]$Key, [object]$Value) {
  $text = if ($null -eq $Value) { '' } else { [string]$Value }
  $text = $text -replace "`r|`n|`t", ' '
  Write-Output ($Key + "`t" + $text)
}
$os = Get-CimInstance Win32_OperatingSystem
Emit 'platform' 'Windows'
Emit 'caption' $os.Caption
Emit 'version' $os.Version
Emit 'build_number' $os.BuildNumber
Emit 'architecture' $os.OSArchitecture
$hotfix = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
Emit 'latest_hotfix' $(if ($hotfix) { $hotfix.HotFixID } else { '' })
Emit 'latest_hotfix_date' $(if ($hotfix -and $hotfix.InstalledOn) { $hotfix.InstalledOn.ToString('yyyy-MM-dd') } else { '' })
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
if ($profiles) {
  foreach ($name in @('Domain','Private','Public')) {
    $profile = $profiles | Where-Object Name -eq $name | Select-Object -First 1
    Emit ("firewall_" + $name.ToLowerInvariant()) $(if ($profile -and $profile.Enabled) { 'enabled' } else { 'disabled' })
  }
} else {
  Emit 'firewall_domain' 'unavailable'
  Emit 'firewall_private' 'unavailable'
  Emit 'firewall_public' 'unavailable'
}
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
Emit 'defender_realtime' $(if ($defender) { if ($defender.RealTimeProtectionEnabled) { 'true' } else { 'false' } } else { 'unavailable' })
$smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
Emit 'smb1_enabled' $(if ($smb) { if ($smb.State -eq 'Enabled') { 'true' } else { 'false' } } else { 'unavailable' })
$pending = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
Emit 'pending_reboot' $(if ($pending) { 'true' } else { 'false' })
$roots = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $roots -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.DisplayVersion } |
  Sort-Object DisplayName, DisplayVersion, Publisher -Unique |
  ForEach-Object {
    $name = ([string]$_.DisplayName) -replace "`r|`n|`t", ' '
    $version = ([string]$_.DisplayVersion) -replace "`r|`n|`t", ' '
    $publisher = ([string]$_.Publisher) -replace "`r|`n|`t", ' '
    Write-Output ('software' + "`t" + $name + "`t" + $version + "`t" + $publisher)
  }
"""


def validate_windows_ssh_user(user: str) -> str:
    value = user.strip()
    if not _WINDOWS_USER_RE.fullmatch(value) or value.startswith("-"):
        raise ValueError("SSH user must be a simple Windows local or DOMAIN\\user account name")
    return value


def _setting(request: ScanRequest, name: str) -> str | None:
    if request.environment and request.environment.get(name):
        return request.environment[name]
    return os.environ.get(name)


def _required_setting(request: ScanRequest, name: str) -> str:
    value = _setting(request, name)
    if not value:
        raise ValueError(f"{name} is required for windows-host scans")
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
    software: dict[tuple[str, str, str], dict[str, str]] = {}
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        if fields[0] == _SOFTWARE_PREFIX:
            if len(fields) != 4 or not fields[1].strip() or not fields[2].strip():
                raise ValueError("Windows host assessment returned malformed software inventory")
            name, version, publisher = (value.strip() for value in fields[1:4])
            software[(name, version, publisher)] = {
                "name": name,
                "version": version,
                "publisher": publisher,
            }
            continue
        key, separator, value = raw_line.partition("\t")
        if separator != "\t" or not key or key in values:
            raise ValueError("Windows host assessment returned malformed output")
        values[key] = value.strip()
    required = {
        "platform",
        "caption",
        "version",
        "build_number",
        "architecture",
        "latest_hotfix",
        "latest_hotfix_date",
        "firewall_domain",
        "firewall_private",
        "firewall_public",
        "defender_realtime",
        "smb1_enabled",
        "pending_reboot",
    }
    if not required.issubset(values):
        raise ValueError("Windows host assessment returned incomplete output")
    for key in ("firewall_domain", "firewall_private", "firewall_public"):
        if values[key].lower() not in _ALLOWED_FIREWALL_STATES:
            raise ValueError("Windows host assessment returned an invalid firewall state")
    for key in ("defender_realtime", "smb1_enabled", "pending_reboot"):
        if values[key].lower() not in _ALLOWED_BOOLEAN_STATES:
            raise ValueError("Windows host assessment returned an invalid security state")
    return values, [software[key] for key in sorted(software)]


def _findings(values: dict[str, str], target: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    disabled_profiles = [
        name.title()
        for name in ("domain", "private", "public")
        if values[f"firewall_{name}"].lower() == "disabled"
    ]
    if disabled_profiles:
        findings.append(
            Finding(
                vulnerability_id="WINDOWS-FIREWALL-PROFILE-DISABLED",
                package_name="windows-firewall",
                installed_version=", ".join(disabled_profiles) + " disabled",
                fixed_version="enable and configure the required Windows Firewall profiles",
                severity="HIGH",
                title="[Windows host] One or more Windows Firewall profiles are disabled",
                target=target,
                package_type="windows-host/firewall",
                primary_url=None,
            )
        )
    if values["defender_realtime"].lower() == "false":
        findings.append(
            Finding(
                vulnerability_id="WINDOWS-DEFENDER-REALTIME-DISABLED",
                package_name="microsoft-defender-antivirus",
                installed_version="real-time protection disabled",
                fixed_version="enable real-time protection or document an approved alternative endpoint security control",
                severity="HIGH",
                title="[Windows host] Microsoft Defender real-time protection is disabled",
                target=target,
                package_type="windows-host/antimalware",
                primary_url=None,
            )
        )
    if values["smb1_enabled"].lower() == "true":
        findings.append(
            Finding(
                vulnerability_id="WINDOWS-SMB1-ENABLED",
                package_name="windows-smb1",
                installed_version="SMB1Protocol enabled",
                fixed_version="disable SMB1 unless a documented legacy dependency requires it",
                severity="HIGH",
                title="[Windows host] SMBv1 is enabled",
                target=target,
                package_type="windows-host/protocol",
                primary_url=None,
            )
        )
    if values["pending_reboot"].lower() == "true":
        findings.append(
            Finding(
                vulnerability_id="WINDOWS-PENDING-REBOOT",
                package_name="operating-system",
                installed_version="pending reboot detected",
                fixed_version="complete the reviewed maintenance reboot",
                severity="LOW",
                title="[Windows host] A reboot is pending",
                target=target,
                package_type="windows-host/patch-posture",
                primary_url=None,
            )
        )
    return tuple(findings)


class WindowsHostScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="windows-host",
            description="authenticated Windows host posture and installed-software inventory over key-based SSH",
            target_help="single Windows hostname or IP address with OpenSSH Server enabled",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        target = validate_network_target(request.target)
        user = validate_windows_ssh_user(_required_setting(request, "SECSCAN_SSH_USER"))
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
            "-l",
            user,
            target,
            "--",
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "-",
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
            raise ValueError("OpenSSH client is required for windows-host assessments") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("Windows host assessment timed out") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            message = detail[-1] if detail else f"exit code {completed.returncode}"
            raise ValueError(f"Windows host SSH assessment failed: {message}")
        values, software = _parse_output(completed.stdout)
        if values["platform"].lower() != "windows":
            raise ValueError("windows-host target did not report Windows")
        findings = _findings(values, target)
        return ScanResult(
            request=request,
            findings=findings,
            raw={
                "schema_version": 1,
                "target": target,
                "host": {
                    "platform": values["platform"],
                    "caption": values["caption"],
                    "version": values["version"],
                    "build_number": values["build_number"],
                    "architecture": values["architecture"],
                    "latest_hotfix": values["latest_hotfix"],
                    "latest_hotfix_date": values["latest_hotfix_date"],
                },
                "checks": {
                    "firewall_domain": values["firewall_domain"],
                    "firewall_private": values["firewall_private"],
                    "firewall_public": values["firewall_public"],
                    "defender_realtime": values["defender_realtime"],
                    "smb1_enabled": values["smb1_enabled"],
                    "pending_reboot": values["pending_reboot"],
                },
                "software_inventory": {
                    "count": len(software),
                    "software": software,
                },
            },
            scanner={"name": "secscan-windows-host", "version": "ssh-posture-software-v1"},
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
