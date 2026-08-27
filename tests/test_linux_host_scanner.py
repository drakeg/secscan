from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.linux_host import LinuxHostScanner, _parse_output, validate_ssh_user


SUCCESS_OUTPUT = """os_kernel\tLinux
kernel_release\t6.8.0
os_id\tubuntu
os_version\t24.04
uid0_accounts\troot,backuproot
ssh_password_auth\tyes
ssh_root_login\tyes
pending_updates\t7
firewall_state\tinactive
world_writable_etc\t/etc/example.conf
package_manager\tdpkg
package\tzlib1g\t1:1.3.dfsg-3.1ubuntu2\tamd64
package\tbase-files\t13ubuntu10\tamd64
"""


def request(tmp_path: Path, *, key_path: Path | None = None) -> ScanRequest:
    key = key_path or (tmp_path / "id_ed25519")
    known_hosts = tmp_path / "known_hosts"
    if key_path is None:
        key.write_text("fixture-private-key", encoding="utf-8")
    known_hosts.write_text("example.test ssh-ed25519 fixture-host-key\n", encoding="utf-8")
    return ScanRequest(scanner_name="linux-host", target="example.test", timeout_seconds=30, output_dir=tmp_path / "reports", environment={"SECSCAN_SSH_USER": "secscan", "SECSCAN_SSH_KEY": str(key), "SECSCAN_SSH_KNOWN_HOSTS": str(known_hosts), "SECSCAN_SSH_PORT": "2222"})


def test_validate_ssh_user_rejects_shell_fragments() -> None:
    assert validate_ssh_user("secscan") == "secscan"
    for value in ("root;id", "user name", "user@host", "-oProxyCommand=x", ""):
        with pytest.raises(ValueError, match="simple Linux username"):
            validate_ssh_user(value)


def test_linux_host_scan_uses_strict_key_only_ssh_and_normalizes_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(command, 0, stdout=SUCCESS_OUTPUT, stderr="")
    monkeypatch.setattr("secscan.scanners.linux_host.validate_network_target", lambda value: value)
    monkeypatch.setattr("secscan.scanners.linux_host.subprocess.run", fake_run)
    result = LinuxHostScanner().scan(request(tmp_path))
    command = captured["command"]
    assert isinstance(command, list)
    command_text = " ".join(command)
    assert "BatchMode=yes" in command
    assert "PasswordAuthentication=no" in command
    assert "KbdInteractiveAuthentication=no" in command
    assert "PreferredAuthentications=publickey" in command
    assert "StrictHostKeyChecking=yes" in command
    assert "ForwardAgent=no" in command
    assert "ForwardX11=no" in command
    assert "-p 2222" in command_text
    assert command[-4:] == ["secscan@example.test", "--", "sh", "-s"]
    assert "fixture-private-key" not in command_text
    assert "fixture-private-key" not in str(result.raw)
    assert "fixture-host-key" not in str(result.raw)
    ids = {finding.vulnerability_id for finding in result.findings}
    assert ids == {"LINUX-UPDATES-PENDING", "SSH-PASSWORD-AUTH-ENABLED", "SSH-ROOT-LOGIN-ENABLED", "LINUX-EXTRA-UID0-ACCOUNTS", "LINUX-HOST-FIREWALL-INACTIVE", "LINUX-WORLD-WRITABLE-ETC-FILES"}
    inventory = result.raw["package_inventory"]  # type: ignore[index]
    assert inventory["manager"] == "dpkg"  # type: ignore[index]
    assert inventory["count"] == 2  # type: ignore[index]
    assert [item["name"] for item in inventory["packages"]] == ["base-files", "zlib1g"]  # type: ignore[index,union-attr]


def test_linux_package_inventory_supports_rpm_and_deduplicates() -> None:
    output = SUCCESS_OUTPUT.replace("package_manager\tdpkg\npackage\tzlib1g\t1:1.3.dfsg-3.1ubuntu2\tamd64\npackage\tbase-files\t13ubuntu10\tamd64\n", "package_manager\trpm\npackage\tzlib\t1:1.3.1-2\tx86_64\npackage\tzlib\t1:1.3.1-2\tx86_64\n")
    values, packages = _parse_output(output)
    assert values["package_manager"] == "rpm"
    assert packages == [{"name": "zlib", "version": "1:1.3.1-2", "architecture": "x86_64", "source": "rpm"}]


def test_linux_package_inventory_allows_unsupported_manager() -> None:
    output = SUCCESS_OUTPUT.replace("package_manager\tdpkg\npackage\tzlib1g\t1:1.3.dfsg-3.1ubuntu2\tamd64\npackage\tbase-files\t13ubuntu10\tamd64\n", "package_manager\tunavailable\n")
    values, packages = _parse_output(output)
    assert values["package_manager"] == "unavailable"
    assert packages == []


def test_linux_package_inventory_rejects_malformed_rows() -> None:
    output = SUCCESS_OUTPUT.replace("package\tzlib1g\t1:1.3.dfsg-3.1ubuntu2\tamd64", "package\tzlib1g\tmissing-architecture")
    with pytest.raises(ValueError, match="malformed package inventory"):
        _parse_output(output)


def test_linux_host_scan_requires_key_and_known_hosts_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("secscan.scanners.linux_host.validate_network_target", lambda value: value)
    with pytest.raises(ValueError, match="SECSCAN_SSH_KEY must point"):
        LinuxHostScanner().scan(request(tmp_path, key_path=tmp_path / "missing"))


def test_linux_host_scan_reports_ssh_failure_without_remote_execution_details(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 255, stdout="", stderr="Host key verification failed.\n")
    monkeypatch.setattr("secscan.scanners.linux_host.validate_network_target", lambda value: value)
    monkeypatch.setattr("secscan.scanners.linux_host.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="Host key verification failed"):
        LinuxHostScanner().scan(request(tmp_path))


def test_linux_host_scan_timeout_is_operational_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, 30)
    monkeypatch.setattr("secscan.scanners.linux_host.validate_network_target", lambda value: value)
    monkeypatch.setattr("secscan.scanners.linux_host.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="timed out"):
        LinuxHostScanner().scan(request(tmp_path))


def test_linux_host_output_rejects_malformed_or_incomplete_data() -> None:
    with pytest.raises(ValueError, match="malformed output"):
        _parse_output("bad-line\n")
    with pytest.raises(ValueError, match="incomplete output"):
        _parse_output("os_kernel\tLinux\n")
