from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from secscan.scanners.base import ScanRequest
from secscan.scanners.registry import build_default_registry
from secscan.scanners.repository import RepositoryScanner, validate_remote_repository_url


def test_default_registry_contains_repository_scanner() -> None:
    registry = build_default_registry()
    assert registry.get("repository").capability.name == "repository"


def test_repository_scanner_rejects_missing_path(tmp_path: Path) -> None:
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="does not exist"):
        scanner.scan(request)


def test_repository_scanner_rejects_file_target(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_text("content", encoding="utf-8")
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(target))
    with pytest.raises(ValueError, match="not a directory"):
        scanner.scan(request)


def test_repository_scanner_normalizes_results(monkeypatch, tmp_path: Path) -> None:
    scanner = RepositoryScanner()
    request = ScanRequest(scanner_name="repository", target=str(tmp_path))
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-REPO",
                        "PkgName": "example",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "Title": "Example repository vulnerability",
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr(
        "secscan.scanners.repository.scan_repository", lambda *_args, **_kwargs: payload
    )
    monkeypatch.setattr(scanner, "_engine_version", lambda: "Trivy test")

    result = scanner.scan(request)

    assert len(result.findings) == 1
    assert result.findings[0].vulnerability_id == "CVE-TEST-REPO"
    assert result.scanner["name"] == "trivy"


def test_remote_repository_is_shallow_cloned_and_cleaned_up(monkeypatch) -> None:
    scanner = RepositoryScanner()
    request = ScanRequest(
        scanner_name="repository",
        target="https://github.com/example/project.git",
        timeout_seconds=30,
    )
    cloned_paths: list[Path] = []
    clone_commands: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        clone_commands.append(args)
        checkout = Path(args[-1])
        checkout.mkdir(parents=True)
        (checkout / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
        assert "shell" not in kwargs
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"]
        return subprocess.CompletedProcess(args, 0, "", "")

    def fake_scan(target: Path, **_kwargs: object) -> dict[str, object]:
        cloned_paths.append(target)
        assert target.is_dir()
        return {"Results": []}

    monkeypatch.setattr("secscan.scanners.repository.subprocess.run", fake_run)
    monkeypatch.setattr("secscan.scanners.repository.scan_repository", fake_scan)
    monkeypatch.setattr(scanner, "_engine_version", lambda: "Trivy test")

    scanner.scan(request)

    assert clone_commands
    assert clone_commands[0][:9] == [
        "git",
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--",
    ]
    assert clone_commands[0][-2] == request.target
    assert len(cloned_paths) == 1
    assert not cloned_paths[0].exists()


def test_github_token_is_process_local_and_not_in_clone_arguments(monkeypatch) -> None:
    token = "github_pat_test_secret_value"
    scanner = RepositoryScanner()
    request = ScanRequest(
        scanner_name="repository",
        target="https://github.com/example/private-project.git",
        timeout_seconds=30,
    )

    monkeypatch.setenv("SECSCAN_GITHUB_TOKEN", token)

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert token not in " ".join(args)
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert environment["GIT_CONFIG_COUNT"] == "1"
        assert environment["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
        assert environment["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")
        assert token not in environment["GIT_CONFIG_VALUE_0"]
        checkout = Path(args[-1])
        checkout.mkdir(parents=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("secscan.scanners.repository.subprocess.run", fake_run)
    monkeypatch.setattr("secscan.scanners.repository.scan_repository", lambda *_args, **_kwargs: {"Results": []})
    monkeypatch.setattr(scanner, "_engine_version", lambda: "Trivy test")

    result = scanner.scan(request)

    assert result.request.target == request.target
    assert token not in result.request.target


def test_git_clone_error_redacts_github_token(monkeypatch) -> None:
    token = "github_pat_test_secret_value"
    scanner = RepositoryScanner()
    request = ScanRequest(
        scanner_name="repository",
        target="https://github.com/example/private-project.git",
        timeout_seconds=30,
    )
    monkeypatch.setenv("SECSCAN_GITHUB_TOKEN", token)

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 128, "", f"fatal: authentication failed for {token}")

    monkeypatch.setattr("secscan.scanners.repository.subprocess.run", fake_run)

    with pytest.raises(ValueError) as exc_info:
        scanner.scan(request)

    message = str(exc_info.value)
    assert token not in message
    assert "[REDACTED]" in message


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("http://github.com/example/project.git", "must use HTTPS"),
        ("https://user:token@github.com/example/project.git", "embedded credentials"),
        ("https://github.com/example/project.git?token=secret", "query strings"),
        ("https://github.com", "repository path"),
    ],
)
def test_remote_repository_url_validation_rejects_unsafe_urls(target: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        validate_remote_repository_url(target)
