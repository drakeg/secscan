from __future__ import annotations

import json
from pathlib import Path

from secscan import cli
from secscan.scanners.base import ScanRequest, ScanResult, Scanner, ScannerCapability


class StubScanner(Scanner):
    @property
    def capability(self) -> ScannerCapability:
        return ScannerCapability("image", "stub image scanner", "image")

    def scan(self, request: ScanRequest) -> ScanResult:
        return ScanResult(request=request, findings=(), raw={}, scanner={"name": "stub"})

    def generate_sbom(self, request: ScanRequest, output_path: Path) -> None:
        output_path.write_text("{}", encoding="utf-8")


class StubRegistry:
    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (StubScanner().capability,)

    def get(self, name: str) -> Scanner:
        assert name == "image"
        return StubScanner()


def test_baseline_is_loaded_before_current_report_is_written(tmp_path: Path, monkeypatch) -> None:
    baseline_path = tmp_path / "secscan.json"
    baseline_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
    baseline_loaded = False

    def load_existing_baseline(path: Path):
        nonlocal baseline_loaded
        assert path == baseline_path
        assert json.loads(path.read_text(encoding="utf-8")) == {"findings": []}
        baseline_loaded = True
        return []

    monkeypatch.setattr(cli, "build_default_registry", lambda: StubRegistry())
    monkeypatch.setattr(cli, "load_baseline", load_existing_baseline)

    exit_code = cli.main(
        [
            "scan",
            "image",
            "alpine:3.20",
            "--baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "NONE",
        ]
    )

    assert exit_code == 0
    assert baseline_loaded is True
    assert (tmp_path / "secscan.diff.json").is_file()
