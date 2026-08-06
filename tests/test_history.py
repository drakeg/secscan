from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from secscan.history import HistoryStore


def test_history_store_migrates_records_lists_and_reads(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)

    scan_id = store.record_scan(
        scanner="image",
        target="alpine:3.20",
        duration_ms=125,
        fail_on="CRITICAL",
        summary={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5},
        report_path=tmp_path / "secscan.json",
        sbom_path=tmp_path / "secscan.cdx.json",
        diff_path=tmp_path / "secscan.diff.json",
        secscan_version="0.1.0",
        scanner_version="0.72.0",
    )

    assert scan_id == 1
    entry = store.get_scan(scan_id)
    assert entry is not None
    assert entry.target == "alpine:3.20"
    assert entry.critical == 1
    assert entry.high == 2
    assert entry.diff_path == str(tmp_path / "secscan.diff.json")
    assert store.list_scans() == [entry]

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]


def test_history_store_rejects_invalid_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        HistoryStore(tmp_path / "secscan.db").list_scans(0)


def test_history_store_filters_and_returns_newest_window_chronologically(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "secscan.db")
    ids: list[int] = []
    for target, critical in [
        ("alpine:3.20", 1),
        ("other:latest", 9),
        ("alpine:3.20", 2),
        ("alpine:3.20", 3),
    ]:
        ids.append(
            store.record_scan(
                scanner="image",
                target=target,
                duration_ms=100,
                fail_on="NONE",
                summary={"CRITICAL": critical},
                report_path=tmp_path / "secscan.json",
                sbom_path=tmp_path / "secscan.cdx.json",
                diff_path=None,
                secscan_version="0.1.0",
                scanner_version="0.72.0",
            )
        )

    entries = store.list_trend_scans(scanner="image", target="alpine:3.20", limit=2)

    assert [entry.id for entry in entries] == [ids[2], ids[3]]
    assert [entry.critical for entry in entries] == [2, 3]
