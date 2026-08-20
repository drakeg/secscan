from __future__ import annotations

from contextlib import contextmanager
import os
import subprocess
from pathlib import Path
import tempfile
from typing import Iterator
from urllib.parse import urlsplit

from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.trivy import generate_repository_cyclonedx, scan_repository


def is_remote_repository_url(target: str) -> bool:
    """Return whether a repository target is expressed as a URL."""
    return "://" in target


def validate_remote_repository_url(target: str) -> str:
    """Validate a public HTTPS Git repository URL without embedded credentials."""
    parsed = urlsplit(target)
    if parsed.scheme.lower() != "https":
        raise ValueError("remote repository URLs must use HTTPS")
    if not parsed.hostname:
        raise ValueError("remote repository URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("remote repository URLs must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("remote repository URLs must not contain query strings or fragments")
    if not parsed.path or parsed.path == "/":
        raise ValueError("remote repository URL must include a repository path")
    return target


class RepositoryScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="repository",
            description="scan a local or remote source repository",
            target_help="repository path or public HTTPS Git URL",
        )

    def scan(self, request: ScanRequest) -> ScanResult:
        with self._resolved_target(request.target, request.timeout_seconds) as target:
            raw = scan_repository(target, timeout_seconds=request.timeout_seconds)
        findings = tuple(normalize_trivy(raw))
        return ScanResult(
            request=request,
            findings=findings,
            raw=raw,
            scanner={"name": "trivy", "version": self._engine_version()},
        )

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        with self._resolved_target(request.target, request.timeout_seconds) as target:
            generate_repository_cyclonedx(
                target,
                output_path,
                timeout_seconds=request.timeout_seconds,
            )

    @classmethod
    @contextmanager
    def _resolved_target(cls, target: str, timeout_seconds: int) -> Iterator[Path]:
        if not is_remote_repository_url(target):
            yield cls._validated_local_target(target)
            return

        remote = validate_remote_repository_url(target)
        with tempfile.TemporaryDirectory(prefix="secscan-repository-") as temporary:
            checkout = Path(temporary) / "repository"
            environment = os.environ.copy()
            environment["GIT_TERMINAL_PROMPT"] = "0"
            try:
                completed = subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "--single-branch",
                        "--no-tags",
                        "--",
                        remote,
                        str(checkout),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    env=environment,
                )
            except FileNotFoundError as exc:
                raise ValueError("git is required to scan remote repositories") from exc
            except subprocess.TimeoutExpired as exc:
                raise ValueError("remote repository clone timed out") from exc
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip().splitlines()
                message = detail[-1] if detail else "git clone failed"
                raise ValueError(f"unable to clone remote repository: {message}")
            yield cls._validated_local_target(str(checkout))

    @staticmethod
    def _validated_local_target(target: str) -> Path:
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise ValueError(f"repository target does not exist: {path}")
        if not path.is_dir():
            raise ValueError(f"repository target is not a directory: {path}")
        if not os.access(path, os.R_OK):
            raise ValueError(f"repository target is not readable: {path}")
        return path

    @staticmethod
    def _engine_version() -> str:
        try:
            completed = subprocess.run(
                ["trivy", "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "unknown"
        return (completed.stdout or completed.stderr).strip().splitlines()[0] or "unknown"
