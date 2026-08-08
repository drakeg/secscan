from __future__ import annotations

import json
from pathlib import Path

from secscan.cli import main


def test_inventory_sbom_cli_writes_json(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "input.spdx.json"
    source.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [{"name": "example", "licenseDeclared": "Apache-2.0"}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "inventory.json"

    exit_code = main(
        ["inventory", "sbom", str(source), "--output", str(output)]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["package_count"] == 1
    assert "packages=1 licensed=1" in capsys.readouterr().out  # type: ignore[attr-defined]


def test_inventory_sbom_cli_reports_invalid_metadata(tmp_path: Path, capsys: object) -> None:
    source = tmp_path / "bad.cdx.json"
    source.write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [{}]}), encoding="utf-8"
    )

    exit_code = main(["inventory", "sbom", str(source), "--output", str(tmp_path / "out.json")])

    assert exit_code == 1
    assert "name is required" in capsys.readouterr().err  # type: ignore[attr-defined]
