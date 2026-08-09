from __future__ import annotations

import json
from pathlib import Path

from secscan.cli import main


def _write(path: Path, packages: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"schema_version": 1, "packages": packages}), encoding="utf-8")


def test_compare_inventory_cli_writes_informational_diff(tmp_path: Path, capsys: object) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    output = tmp_path / "diff.json"
    _write(baseline, [])
    _write(
        current,
        [{"name": "added", "version": "1", "purl": None, "declared_licenses": []}],
    )

    exit_code = main(
        ["compare", "inventory", str(baseline), str(current), "--output", str(output)]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["added"] == 1
    assert '"added": 1' in capsys.readouterr().out  # type: ignore[attr-defined]


def test_compare_inventory_cli_rejects_missing_file(tmp_path: Path, capsys: object) -> None:
    current = tmp_path / "current.json"
    _write(current, [])

    exit_code = main(
        ["compare", "inventory", str(tmp_path / "missing.json"), str(current)]
    )

    assert exit_code == 1
    assert "inventory is not a file" in capsys.readouterr().err  # type: ignore[attr-defined]
