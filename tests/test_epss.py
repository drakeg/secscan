from __future__ import annotations

from pathlib import Path

import pytest

from secscan.epss import enrich_finding_documents, load_epss_scores


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


def test_epss_requires_absolute_existing_path(tmp_path: Path) -> None:
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
