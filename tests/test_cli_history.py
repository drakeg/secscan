from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from secscan.cli import main
from secscan.history import HistoryStore
from secscan.models import Finding


def _finding(vulnerability_id: str, package: str) -> Finding:
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


def _record(
    store: HistoryStore,
    tmp_path: Path,
    critical: int,
    *,
    target: str = "alpine:3.20",
    findings: tuple[Finding, ...] | None = None,
) -> int:
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
        findings=findings,
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


def test_finding_changes_writes_latest_exact_cohort_transition(tmp_path: Path) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    common = _finding("CVE-2026-0001", "openssl")
    resolved = _finding("CVE-2026-0002", "libxml2")
    new = _finding("CVE-2026-0003", "zlib")
    previous = _record(store, tmp_path, 0, findings=(common, resolved))
    _record(store, tmp_path, 0, target="other:latest", findings=(new,))
    current = _record(store, tmp_path, 0, findings=(common, new))
    output = tmp_path / "finding-changes.json"

    exit_code = main(
        [
            "finding-changes",
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
    assert document["previous_scan"]["id"] == previous
    assert document["current_scan"]["id"] == current
    assert document["summary"] == {"new": 1, "resolved": 1, "unchanged": 1}
    assert [item["vulnerability_id"] for item in document["new"]] == ["CVE-2026-0003"]
    assert [item["vulnerability_id"] for item in document["resolved"]] == [
        "CVE-2026-0002"
    ]


def test_finding_changes_requires_two_finding_level_scans(
    tmp_path: Path, capsys: object
) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    _record(store, tmp_path, 0)
    _record(store, tmp_path, 0, findings=(_finding("CVE-2026-0001", "openssl"),))

    assert main(
        [
            "finding-changes",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
        ]
    ) == 1
    assert "2 finding-level scans are required" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_finding_changes_treats_empty_recorded_scan_as_resolution(
    tmp_path: Path,
) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    _record(
        store,
        tmp_path,
        0,
        findings=(_finding("CVE-2026-0001", "openssl"),),
    )
    _record(store, tmp_path, 0, findings=())
    output = tmp_path / "finding-changes.json"

    assert main(
        [
            "finding-changes",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
            "--output",
            str(output),
        ]
    ) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"] == {
        "new": 0,
        "resolved": 1,
        "unchanged": 0,
    }


def test_finding_timing_separates_censored_measured_and_open_episodes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    finding_a = _finding("CVE-2026-0001", "openssl")
    finding_b = _finding("CVE-2026-0002", "libxml2")
    scan_ids = [
        _record(store, tmp_path, 0, findings=(finding_a,)),
        _record(store, tmp_path, 0, findings=()),
        _record(store, tmp_path, 0, findings=(finding_b,)),
        _record(store, tmp_path, 0, findings=()),
        _record(store, tmp_path, 0, findings=(finding_b,)),
    ]
    timestamps = [
        "2026-08-14 10:00:00",
        "2026-08-14 11:00:00",
        "2026-08-14 12:00:00",
        "2026-08-14 13:00:00",
        "2026-08-14 14:00:00",
    ]
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "UPDATE scans SET created_at = ? WHERE id = ?",
            zip(timestamps, scan_ids, strict=True),
        )
    output = tmp_path / "finding-timing.json"

    assert main(
        [
            "finding-timing",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
            "--limit",
            "5",
            "--output",
            str(output),
        ]
    ) == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["window"]["scan_count"] == 5
    assert document["summary"] == {
        "resolved_episode_count": 2,
        "open_episode_count": 1,
        "left_censored_episode_count": 1,
        "measurable_resolved_count": 1,
        "mean_observed_resolution_seconds": 3600.0,
    }
    assert document["resolved_episodes"][0]["left_censored"] is True
    assert document["resolved_episodes"][0]["observed_resolution_seconds"] is None
    assert document["resolved_episodes"][1]["observed_resolution_seconds"] == 3600
    assert document["open_episodes"][0]["finding"]["vulnerability_id"] == "CVE-2026-0002"


def test_finding_timing_rejects_invalid_limit(tmp_path: Path, capsys: object) -> None:
    assert main(
        [
            "finding-timing",
            "--history-db",
            str(tmp_path / "secscan.db"),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
            "--limit",
            "101",
        ]
    ) == 1
    assert "between 2 and 100" in capsys.readouterr().err  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("resolved_at", "message"),
    [
        ("not-a-timestamp", "invalid scan history timestamp"),
        ("2026-08-14 11:00:00", "timestamps must be chronological"),
    ],
)
def test_finding_timing_rejects_invalid_observation_timestamps(
    tmp_path: Path, capsys: object, resolved_at: str, message: str
) -> None:
    database = tmp_path / "secscan.db"
    store = HistoryStore(database)
    scan_ids = [
        _record(store, tmp_path, 0, findings=()),
        _record(
            store,
            tmp_path,
            0,
            findings=(_finding("CVE-2026-0001", "openssl"),),
        ),
        _record(store, tmp_path, 0, findings=()),
    ]
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "UPDATE scans SET created_at = ? WHERE id = ?",
            zip(
                ["2026-08-14 10:00:00", "2026-08-14 12:00:00", resolved_at],
                scan_ids,
                strict=True,
            ),
        )

    assert main(
        [
            "finding-timing",
            "--history-db",
            str(database),
            "--scanner",
            "image",
            "--target",
            "alpine:3.20",
        ]
    ) == 1
    assert message in capsys.readouterr().err  # type: ignore[attr-defined]
