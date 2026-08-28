from __future__ import annotations

from pathlib import Path

import pytest

from secscan.epss import enrich_finding_documents, load_epss_scores
from secscan.models import Finding
from secscan.report import build_report


def _scores(path: Path) -> Path:
    path.write_text(
        "#model_version:v2026.06.15,score_date:2026-08-27T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.42,0.97\n"
        "CVE-2025-9999,0.005,0.40\n",
        encoding="utf-8",
    )
    return path


def test_load_and_enrich_epss_scores(tmp_path: Path) -> None:
    scores = load_epss_scores(_scores(tmp_path / "epss.csv"))
    findings, scored, max_score = enrich_finding_documents(
        [
            {"vulnerability_id": "cve-2024-1234", "severity": "HIGH"},
            {"vulnerability_id": "CVE-2024-0001", "severity": "CRITICAL"},
        ],
        scores,
    )

    assert scored == 1
    assert max_score == pytest.approx(0.42)
    assert findings[0]["epss"] == {"score": 0.42, "percentile": 0.97}
    assert "epss" not in findings[1]


def test_build_report_uses_opt_in_local_epss_scores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    score_path = _scores(tmp_path / "epss.csv")
    monkeypatch.delenv("SECSCAN_KEV_CATALOG", raising=False)
    monkeypatch.setenv("SECSCAN_EPSS_CSV", str(score_path))
    report = build_report(
        "example",
        [
            Finding(
                vulnerability_id="CVE-2024-1234",
                package_name="example",
                installed_version="1.0",
                fixed_version="1.1",
                severity="HIGH",
                title="Example",
                target="example",
                package_type="os",
                primary_url=None,
            )
        ],
        {"name": "test", "version": "1"},
    )

    assert report["schema_version"] == "1.2"
    assert report["summary"]["epss_scored"] == 1
    assert report["summary"]["max_epss_score"] == pytest.approx(0.42)
    assert report["enrichment"]["epss"] == {
        "status": "enabled",
        "scored_findings": 1,
        "score_entries": 2,
        "max_score": pytest.approx(0.42),
    }
    assert report["findings"][0]["epss"] == {"score": 0.42, "percentile": 0.97}


def test_build_report_keeps_epss_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECSCAN_KEV_CATALOG", raising=False)
    monkeypatch.delenv("SECSCAN_EPSS_CSV", raising=False)
    report = build_report("example", [], {"name": "test", "version": "1"})
    assert report["schema_version"] == "1.0"
    assert report["enrichment"]["epss"] == {
        "status": "disabled",
        "scored_findings": 0,
    }


def test_epss_requires_absolute_existing_path() -> None:
    with pytest.raises(ValueError, match="absolute CSV file"):
        load_epss_scores(Path("epss.csv"))


def test_epss_rejects_wrong_header(tmp_path: Path) -> None:
    path = tmp_path / "epss.csv"
    path.write_text("cve,epss\nCVE-2024-1234,0.1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header must be exactly"):
        load_epss_scores(path)


def test_epss_rejects_duplicate_cves(tmp_path: Path) -> None:
    path = tmp_path / "epss.csv"
    path.write_text(
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.1,0.5\n"
        "cve-2024-1234,0.2,0.6\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate CVE-2024-1234"):
        load_epss_scores(path)


@pytest.mark.parametrize("field,value", [("epss", "-0.1"), ("epss", "1.1"), ("percentile", "nan")])
def test_epss_rejects_invalid_probabilities(tmp_path: Path, field: str, value: str) -> None:
    row = {"epss": "0.1", "percentile": "0.5"}
    row[field] = value
    path = tmp_path / "epss.csv"
    path.write_text(
        f"cve,epss,percentile\nCVE-2024-1234,{row['epss']},{row['percentile']}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="between 0 and 1"):
        load_epss_scores(path)
