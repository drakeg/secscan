from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping


class TrivyError(RuntimeError):
    pass


def _run_trivy(
    command: list[str],
    output_path: Path,
    timeout_seconds: int,
    environment: Mapping[str, str] | None = None,
) -> None:
    process_environment = None
    if environment is not None:
        process_environment = dict(os.environ)
        process_environment.update(environment)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=process_environment,
        )
    except FileNotFoundError as exc:
        raise TrivyError("Trivy is not installed or is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"Trivy scan exceeded {timeout_seconds} seconds") from exc

    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown Trivy error"
        raise TrivyError(message)
    if not output_path.exists():
        raise TrivyError("Trivy did not create the expected output artifact")


def _read_json_output(output_path: Path) -> dict[str, Any]:
    try:
        return json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrivyError("Trivy did not produce valid JSON output") from exc


def _scan_path(mode: str, target: Path, timeout_seconds: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="secscan-") as temp_dir:
        output_path = Path(temp_dir) / "trivy.json"
        _run_trivy(
            [
                "trivy",
                mode,
                "--format",
                "json",
                "--output",
                str(output_path),
                "--quiet",
                str(target),
            ],
            output_path,
            timeout_seconds,
        )
        return _read_json_output(output_path)


def _trivy_compatible_sbom(target: Path, temp_dir: Path) -> Path:
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return target
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        return target
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return target
    component = metadata.get("component")
    if not isinstance(component, dict) or component.get("type") != "device":
        return target

    compatible = dict(payload)
    compatible_metadata = dict(metadata)
    compatible_component = dict(component)
    compatible_component["type"] = "application"
    compatible_metadata["component"] = compatible_component
    compatible["metadata"] = compatible_metadata
    compatible_path = temp_dir / "trivy-compatible.cdx.json"
    compatible_path.write_text(
        json.dumps(compatible, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return compatible_path


def _generate_path_cyclonedx(
    mode: str, target: Path, output_path: Path, timeout_seconds: int
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run_trivy(
        [
            "trivy",
            mode,
            "--format",
            "cyclonedx",
            "--output",
            str(output_path),
            "--quiet",
            str(target),
        ],
        output_path,
        timeout_seconds,
    )


def scan_image(
    image: str,
    timeout_seconds: int = 600,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="secscan-") as temp_dir:
        output_path = Path(temp_dir) / "trivy.json"
        _run_trivy(
            [
                "trivy",
                "image",
                "--format",
                "json",
                "--output",
                str(output_path),
                "--quiet",
                image,
            ],
            output_path,
            timeout_seconds,
            environment,
        )
        return _read_json_output(output_path)


def scan_filesystem(target: Path, timeout_seconds: int = 600) -> dict[str, Any]:
    return _scan_path("filesystem", target, timeout_seconds)


def scan_repository(target: Path, timeout_seconds: int = 600) -> dict[str, Any]:
    return _scan_path("repository", target, timeout_seconds)


def scan_sbom(target: Path, timeout_seconds: int = 600) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="secscan-sbom-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        compatible_target = _trivy_compatible_sbom(target, temp_dir)
        return _scan_path("sbom", compatible_target, timeout_seconds)


def generate_cyclonedx(
    image: str,
    output_path: Path,
    timeout_seconds: int = 600,
    environment: Mapping[str, str] | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run_trivy(
        [
            "trivy",
            "image",
            "--format",
            "cyclonedx",
            "--output",
            str(output_path),
            "--quiet",
            image,
        ],
        output_path,
        timeout_seconds,
        environment,
    )


def generate_filesystem_cyclonedx(
    target: Path, output_path: Path, timeout_seconds: int = 600
) -> None:
    _generate_path_cyclonedx("filesystem", target, output_path, timeout_seconds)


def generate_repository_cyclonedx(
    target: Path, output_path: Path, timeout_seconds: int = 600
) -> None:
    _generate_path_cyclonedx("repository", target, output_path, timeout_seconds)
