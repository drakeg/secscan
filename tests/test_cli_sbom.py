from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from secscan import cli
from secscan.scanners.sbom import SBOMScanner


def test_spdx_scan_uses_format_specific_artifact_and_history(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "input.spdx.json"
    source.write_text(
        json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}), encoding="utf-8"
    )
    output_dir = tmp_path / "reports"
    monkeypatch.setattr("secscan.scanners.sbom.scan_sbom", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(SBOMScanner, "_engine_version", staticmethod(lambda: "Trivy test"))

    exit_code = cli.main(
        [
            "scan",
            "sbom",
            str(source),
            "--output-dir",
            str(output_dir),
            "--fail-on",
            "NONE",
        ]
    )

    preserved = output_dir / "secscan.spdx.json"
    assert exit_code == 0
    assert preserved.read_bytes() == source.read_bytes()
    assert not (output_dir / "secscan.cdx.json").exists()
    with sqlite3.connect(output_dir / "secscan.db") as connection:
        assert connection.execute("SELECT sbom_path FROM scans").fetchone() == (str(preserved),)
