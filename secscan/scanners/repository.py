from __future__ import annotations

from base64 import b64encode
from contextlib import contextmanager
from dataclasses import dataclass
import os
import subprocess
from pathlib import Path
import tempfile
from typing import Iterator, Protocol
from urllib.parse import SplitResult, urlsplit

from secscan.normalize import normalize_trivy
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability
from secscan.trivy import generate_repository_cyclonedx, scan_repository


GITHUB_TOKEN_ENV = "SECSCAN_GITHUB_TOKEN"


def is_remote_repository_url(target: str) -> bool:
    """Return whether a repository target is expressed as a URL."""
    return "://" in target


def validate_remote_repository_url(target: str) -> str:
    """Validate an HTTPS Git repository URL without embedded credentials."""
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


class RepositoryAuthProvider(Protocol):
    """Provide process-local Git authentication for one repository host."""

    def configure(self, remote: SplitResult, environment: dict[str, str]) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class GitHubEnvironmentAuthProvider:
    """Use a server-side GitHub token without persisting it in Git configuration."""

    token_env: str = GITHUB_TOKEN_ENV

    def configure(self, remote: SplitResult, environment: dict[str, str]) -> tuple[str, ...]:
        if (remote.hostname or "").lower() != "github.com":
            return ()
        token = os.environ.get(self.token_env, "")
        if not token:
            return ()
        if token != token.strip() or any(character.isspace() for character in token):
            raise ValueError(f"{self.token_env} must not contain whitespace")

        credential = b64encode(f"x-access-token:{token}".encode()).decode("ascii")
        environment["GIT_CONFIG_COUNT"] = "1"
        environment["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
        environment["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {credential}"
        return (token, credential)


_AUTH_PROVIDERS: tuple[RepositoryAuthProvider, ...] = (GitHubEnvironmentAuthProvider(),)


def _redact_secret(value: str, secrets: tuple[str, ...]) -> str:
    redacted = value
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _clone_environment(remote: SplitResult) -> tuple[dict[str, str], tuple[str, ...]]:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    secrets: list[str] = []
    for provider in _AUTH_PROVIDERS:
        secrets.extend(provider.configure(remote, environment))
    return environment, tuple(secrets)


class RepositoryScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability(
            name="repository-trivy",
            description="run the legacy Trivy-only repository scan",
            target_help="repository path or HTTPS Git URL",
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

        remote_url = validate_remote_repository_url(target)
        remote = urlsplit(remote_url)
        environment, secrets = _clone_environment(remote)
        with tempfile.TemporaryDirectory(prefix="secscan-repository-") as temporary:
            checkout = Path(temporary) / "repository"
            try:
                completed = subprocess.run(
                    [
                        "git",
                        "-c",
                        "credential.helper=",
                        "clone",
                        "--depth",
                        "1",
                        "--single-branch",
                        "--no-tags",
                        "--",
                        remote_url,
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
                message = _redact_secret(message, secrets)
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
