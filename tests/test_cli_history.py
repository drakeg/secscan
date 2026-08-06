from __future__ import annotations

import json
from pathlib import Path

from secscan.cli import main
from secscan.history import HistoryStore


def _record(store: HistoryStore, tmp_path: Path, critical: int, *, target: str = "alpine:3.20") -> int:
    return store.record_scan(
        scanner="image",
        target=target,
        duration_ms=100 + critical,
        fail_on="NONE",
        summary={"CRITICAL": critical, "HIGH": 4 - critical, "MEDIUM": 2},
        report_path=tmp_path / "secscan.json",
        sbom_path=tmp_path / "secscan.cdx.json",
        diff_path=None,
        secscan_version="0.1.0",
        scanner_version="0.72.0",
    )


def test_trends_writes_versioned_json_for_exact_cohort(tmp_path: Path, capsys: object) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    first = _record(store, tmp_path, 3)
    _record(store, tmp_path, 9, target="other:latest")
    second = _record(store, tmp_path, 1)
    output = tmp_path / "nested" / "trend.json"

    exit_code = main(
        [
            "trends",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["scanner"] == "image"
    assert document["target"] == "alpine:3.20"
    assert document["scan_count"] == 2
    assert document["latest"]["critical"] == 1
    assert document["change_since_oldest"]["critical"] == -2
    assert [point["scan_id"] for point in document["series"]] == [first, second]
    assert not list(output.parent.glob("*.tmp"))


def test_trends_prints_series_and_signed_changes(tmp_path: Path, capsys: object) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    _record(store, tmp_path, 1)
    _record(store, tmp_path, 2)

    exit_code = main(
        [
            "trends",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "Trend: image alpine:3.20 (2 scans)" in output
    assert "CRITICAL=+1" in output


def test_trends_rejects_invalid_limit(tmp_path: Path, capsys: object) -> None:
    exit_code = main(
        [
            "trends",
            "--history-db",
            str(tmp_path / "secscan.db"),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
            "--limit",
            "101",
        ]
    )

    assert exit_code == 1
    assert "between 2 and 100" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_trends_requires_two_matching_scans(tmp_path: Path, capsys: object) -> None:
    database = tmp_path / "secscan.db"
    _record(HistoryStore(database), tmp_path, 1)

    exit_code = main(
        [
            "trends",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
        ]
    )

    assert exit_code == 1
    assert "at least 2 matching scans" in capsys.readouterr().err  # type: ignore[attr-defined]
