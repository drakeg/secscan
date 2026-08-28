from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.windows_host import WindowsHostScanner, _parse_output, validate_windows_ssh_user


SUCCESS_OUTPUT = """platform\tWindows
caption\tMicrosoft Windows Server 2025 Datacenter
version\t10.0.26100
build_number\t26100
architecture\t64-bit
latest_hotfix\tKB5060000
latest_hotfix_date\t2026-08-12
firewall_domain\tenabled
firewall_private\tdisabled
firewall_public\tenabled
defender_realtime\tfalse
smb1_enabled\ttrue
pending_reboot\ttrue
software\t7-Zip 24.09\t24.09\tIgor Pavlov
software\tGit\t2.51.0\tThe Git Development Community
"""


def request(tmp_path: Path, *, key_path: Path | None = None) -> ScanRequest:
    key = key_path or (tmp_path / "id_ed25519")
    known_hosts = tmp_path / "known_hosts"
    if key_path is None:
        key.write_text("fixture-private-key", encoding="utf-8")
    known_hosts.write_text("windows.example ssh-ed25519 fixture-host-key\n", encoding="utf-8")
    return ScanRequest(
        scanner_name="windows-host",
        target="windows.example",
        timeout_seconds=30,
        output_dir=tmp_path / "reports",
        environment={
            "SECSCAN_SSH_USER": "CONTOSO\\secscan",
            "SECSCAN_SSH_KEY": str(key),
            "SECSCAN_SSH_KNOWN_HOSTS": str(known_hosts),
            "SECSCAN_SSH_PORT": "2222",
        },
    )


def test_validate_windows_ssh_user_rejects_shell_fragments() -> None:
    assert validate_windows_ssh_user("secscan") == "secscan"
    assert validate_windows_ssh_user("CONTOSO\\secscan") == "CONTOSO\\secscan"
    for value in ("user name", "user@domain", "-oProxyCommand=x", "user;whoami", ""):
        with pytest.raises(ValueError, match="simple Windows"):
            validate_windows_ssh_user(value)


def test_windows_host_scan_uses_strict_key_only_ssh_and_normalizes_posture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(command, 0, stdout=SUCCESS_OUTPUT, stderr="")

    monkeypatch.setattr("secscan.scanners.windows_host.validate_network_target", lambda value: value)
    monkeypatch.setattr("secscan.scanners.windows_host.subprocess.run", fake_run)

    result = WindowsHostScanner().scan(request(tmp_path))
    command = captured["command"]
    assert isinstance(command, list)
    command_text = " ".join(command)
    for option in (
        "BatchMode=yes",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "PreferredAuthentications=publickey",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
    ):
        assert option in command
    assert "-p 2222" in command_text
    assert command[-9:] == [
        "windows.example",
        "--",
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "-",
    ][-9:]
    assert "fixture-private-key" not in command_text
    assert "fixture-private-key" not in str(result.raw)
    assert "fixture-host-key" not in str(result.raw)

    ids = {finding.vulnerability_id for finding in result.findings}
    assert ids == {
        "WINDOWS-FIREWALL-PROFILE-DISABLED",
        "WINDOWS-DEFENDER-REALTIME-DISABLED",
        "WINDOWS-SMB1-ENABLED",
        "WINDOWS-PENDING-REBOOT",
    }
    assert result.raw["host"]["build_number"] == "26100"  # type: ignore[index]
    inventory = result.raw["software_inventory"]  # type: ignore[index]
    assert inventory["count"] == 2  # type: ignore[index]
    assert [item["name"] for item in inventory["software"]] == ["7-Zip 24.09", "Git"]  # type: ignore[index,union-attr]


def test_windows_output_deduplicates_software_and_validates_states() -> None:
    values, software = _parse_output(SUCCESS_OUTPUT + "software\tGit\t2.51.0\tThe Git Development Community\n")
    assert values["platform"] == "Windows"
    assert len(software) == 2
    with pytest.raises(ValueError, match="invalid firewall state"):
        _parse_output(SUCCESS_OUTPUT.replace("firewall_public\tenabled", "firewall_public\tmaybe"))
    with pytest.raises(ValueError, match="invalid security state"):
        _parse_output(SUCCESS_OUTPUT.replace("smb1_enabled\ttrue", "smb1_enabled\tmaybe"))


def test_windows_host_scan_requires_key_and_known_hosts_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("secscan.scanners.windows_host.validate_network_target", lambda value: value)
    with pytest.raises(ValueError, match="SECSCAN_SSH_KEY must point"):
        WindowsHostScanner().scan(request(tmp_path, key_path=tmp_path / "missing"))


def test_windows_host_scan_rejects_non_windows_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = SUCCESS_OUTPUT.replace("platform\tWindows", "platform\tLinux")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr("secscan.scanners.windows_host.validate_network_target", lambda value: value)
    monkeypatch.setattr("secscan.scanners.windows_host.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="did not report Windows"):
        WindowsHostScanner().scan(request(tmp_path))


def test_windows_host_scan_reports_ssh_failure_and_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("secscan.scanners.windows_host.validate_network_target", lambda value: value)

    def failed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 255, stdout="", stderr="Host key verification failed.\n")

    monkeypatch.setattr("secscan.scanners.windows_host.subprocess.run", failed)
    with pytest.raises(ValueError, match="Host key verification failed"):
        WindowsHostScanner().scan(request(tmp_path))

    def timed_out(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, 30)

    monkeypatch.setattr("secscan.scanners.windows_host.subprocess.run", timed_out)
    with pytest.raises(ValueError, match="timed out"):
        WindowsHostScanner().scan(request(tmp_path))


def test_windows_host_output_rejects_malformed_or_incomplete_data() -> None:
    with pytest.raises(ValueError, match="malformed output"):
        _parse_output("bad-line\n")
    with pytest.raises(ValueError, match="incomplete output"):
        _parse_output("platform\tWindows\n")
    with pytest.raises(ValueError, match="malformed software inventory"):
        _parse_output(SUCCESS_OUTPUT.replace("software\tGit\t2.51.0\tThe Git Development Community", "software\tGit"))
