from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.release_artifacts import project_version, verify_release_tag, write_checksums


def _pyproject(path: Path, version: str = "1.2.3") -> None:
    path.write_text(f'[project]\nname = "example"\nversion = "{version}"\n', encoding="utf-8")


def test_release_tag_must_exactly_match_project_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _pyproject(pyproject)

    assert project_version(pyproject) == "1.2.3"
    assert verify_release_tag("v1.2.3", pyproject) == "1.2.3"
    with pytest.raises(ValueError, match="does not match"):
        verify_release_tag("v1.2.4", pyproject)


@pytest.mark.parametrize(
    "tag",
    ["1.2.3", "v1.2", "v01.2.3", "v1.2.3-rc1", "v1.2.3+build", "release-v1.2.3"],
)
def test_release_tag_rejects_unsupported_formats(tmp_path: Path, tag: str) -> None:
    pyproject = tmp_path / "pyproject.toml"
    _pyproject(pyproject)

    with pytest.raises(ValueError, match="vMAJOR.MINOR.PATCH"):
        verify_release_tag(tag, pyproject)


def test_checksums_are_sorted_and_deterministic(tmp_path: Path) -> None:
    second = tmp_path / "secscan.tar.gz"
    first = tmp_path / "secscan.whl"
    second.write_bytes(b"source")
    first.write_bytes(b"wheel")
    output = tmp_path / "SHA256SUMS"

    write_checksums(output, [second, first])
    initial = output.read_bytes()
    write_checksums(output, [first, second])

    assert output.read_bytes() == initial
    assert output.read_text(encoding="utf-8").splitlines() == [
        f"{hashlib.sha256(b'source').hexdigest()}  secscan.tar.gz",
        f"{hashlib.sha256(b'wheel').hexdigest()}  secscan.whl",
    ]


def test_checksums_reject_missing_duplicate_and_self_reference(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"wheel")
    output = tmp_path / "SHA256SUMS"

    with pytest.raises(ValueError, match="at least one"):
        write_checksums(output, [])
    with pytest.raises(ValueError, match="not a regular file"):
        write_checksums(output, [tmp_path / "missing.whl"])
    with pytest.raises(ValueError, match="duplicate"):
        write_checksums(output, [artifact, artifact])
    output.write_text("existing", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot include itself"):
        write_checksums(output, [output])
