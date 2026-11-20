from __future__ import annotations

from pathlib import Path

from scripts.check_readme_badges import END, START, problems


ROOT = Path(__file__).resolve().parent.parent


def test_current_readme_badges_match_verified_repository_configuration() -> None:
    assert problems((ROOT / "README.md").read_text(encoding="utf-8")) == []


def test_duplicate_or_missing_marker_fails_closed() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert problems(readme.replace(END, "")) != []
    assert problems(readme + "\n" + START + "\n" + END) != []


def test_missing_dynamic_workflow_and_statistics_badges_are_detected() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert any("ci.yml" in message for message in problems(readme.replace("/ci.yml/badge.svg", "/ci.yml/bogus.svg")))
    assert any("dynamic issues" in message for message in problems(
        readme.replace("img.shields.io/github/issues/drakeg/secscan", "img.shields.io/github/issues/someone/else")
    ))


def test_badges_must_follow_title_and_never_claim_unverified_license_or_release() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert problems(readme.replace(START, "Intro prose\n\n" + START))
    assert any("license" in message for message in problems(
        readme.replace(END, "[![License](https://img.shields.io/github/license/drakeg/secscan)](fake)\n" + END)
    ))
    assert any("release" in message for message in problems(
        readme.replace(END, "[![Release](https://img.shields.io/github/v/release/drakeg/secscan)](fake)\n" + END)
    ))
