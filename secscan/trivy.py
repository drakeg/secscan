from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class TrivyError(RuntimeError):
    pass


def _run_trivy(command: list[str], output_path: Path, timeout_seconds: int) -> None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
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


def scan_image(image: str, timeout_seconds: int = 600) -> dict[str, Any]:
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
        )
        try:
            return json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TrivyError("Trivy did not produce valid JSON output") from exc


def generate_cyclonedx(image: str, output_path: Path, timeout_seconds: int = 600) -> None:
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
    )
