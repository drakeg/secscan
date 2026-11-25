from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "secscan_readme_badge_validator", ROOT / "scripts" / "check_readme_badges.py"
)
assert spec is not None and spec.loader is not None
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
START = validator.START
END = validator.END
problems = validator.problems


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
    import re
    without_license_badge = re.sub(
        r"\[!\[License\]\(https://img\.shields\.io/github/license/drakeg/secscan\)\]\([^)]*\)",
        "", readme,
    )
    assert without_license_badge != readme
    assert any("license" in message for message in problems(without_license_badge))
    assert any("release" in message for message in problems(
        readme.replace(END, "[![Release](https://img.shields.io/github/v/release/drakeg/secscan)](fake)\n" + END)
    ))
