from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from secscan.history import HistoryStore
from secscan.models import Finding


def _finding(vulnerability_id: str, package: str = "openssl") -> Finding:
    return Finding(
        vulnerability_id=vulnerability_id,
        package_name=package,
        installed_version="1.0",
        fixed_version="1.1",
        severity="HIGH",
        title="Example",
        target="alpine:3.20 (apk)",
        package_type="apk",
        primary_url=None,
    )


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
        assert connection.execute("SELECT version FROM schema_migrations").fetchall() == [
            (1,),
            (2,),
        ]


def test_history_store_rejects_invalid_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        HistoryStore(tmp_path / "secscan.db").list_scans(0)


def test_history_store_migrates_version_one_database_without_inventing_findings(
    tmp_path: Path,
) -> None:
    database = tmp_path / "secscan.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
            INSERT INTO schema_migrations(version) VALUES (1);
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                scanner TEXT NOT NULL,
                target TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                fail_on TEXT NOT NULL,
                critical INTEGER NOT NULL,
                high INTEGER NOT NULL,
                medium INTEGER NOT NULL,
                low INTEGER NOT NULL,
                unknown INTEGER NOT NULL,
                report_path TEXT NOT NULL,
                sbom_path TEXT NOT NULL,
                diff_path TEXT,
                secscan_version TEXT NOT NULL,
                scanner_version TEXT NOT NULL
            );
            INSERT INTO scans (
                scanner, target, duration_ms, fail_on, critical, high, medium,
                low, unknown, report_path, sbom_path, secscan_version, scanner_version
            ) VALUES (
                'image', 'alpine:3.20', 100, 'NONE', 0, 1, 0, 0, 0,
                'secscan.json', 'secscan.cdx.json', '0.1.0', '0.72.0'
            );
            """
        )

    store = HistoryStore(database)
    entry = store.get_scan(1)

    assert entry is not None
    assert entry.findings_recorded == 0
    assert store.latest_finding_observations(
        scanner="image", target="alpine:3.20"
    ) == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version FROM schema_migrations").fetchall() == [
            (1,),
            (2,),
        ]


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


def test_history_store_records_two_latest_finding_observations(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "secscan.db")
    common = _finding("CVE-2026-0001")
    resolved = _finding("CVE-2026-0002", "libxml2")
    new = _finding("CVE-2026-0003", "zlib")
    first = store.record_scan(
        scanner="image",
        target="alpine:3.20",
        duration_ms=100,
        fail_on="NONE",
        summary={"HIGH": 2},
        report_path=tmp_path / "first.json",
        sbom_path=tmp_path / "first.cdx.json",
        diff_path=None,
        secscan_version="0.1.0",
        scanner_version="0.72.0",
        findings=(common, resolved),
    )
    second = store.record_scan(
        scanner="image",
        target="alpine:3.20",
        duration_ms=100,
        fail_on="NONE",
        summary={"HIGH": 2},
        report_path=tmp_path / "second.json",
        sbom_path=tmp_path / "second.cdx.json",
        diff_path=None,
        secscan_version="0.1.0",
        scanner_version="0.72.0",
        findings=(common, new),
    )

    observations = store.latest_finding_observations(
        scanner="image", target="alpine:3.20"
    )

    assert [scan.id for scan, _ in observations] == [first, second]
    assert [
        {item.vulnerability_id for item in items} for _, items in observations
    ] == [
        {"CVE-2026-0001", "CVE-2026-0002"},
        {"CVE-2026-0001", "CVE-2026-0003"},
    ]


def test_duplicate_finding_fingerprint_rolls_back_scan(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "secscan.db")
    finding = _finding("CVE-2026-0001")

    with pytest.raises(ValueError, match="duplicate finding fingerprints"):
        store.record_scan(
            scanner="image",
            target="alpine:3.20",
            duration_ms=100,
            fail_on="NONE",
            summary={"HIGH": 2},
            report_path=tmp_path / "secscan.json",
            sbom_path=tmp_path / "secscan.cdx.json",
            diff_path=None,
            secscan_version="0.1.0",
            scanner_version="0.72.0",
            findings=(finding, finding),
        )

    assert store.list_scans() == []
