from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import tomllib

VERSION_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def project_version(pyproject: Path) -> str:
    try:
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        version = payload["project"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"unable to read project.version from {pyproject}") from exc
    if not isinstance(version, str) or not version.strip():
        raise ValueError("project.version must be a non-empty string")
    return version.strip()


def verify_release_tag(tag: str, pyproject: Path) -> str:
    match = VERSION_TAG.fullmatch(tag)
    if match is None:
        raise ValueError("release tag must use exact stable vMAJOR.MINOR.PATCH format")
    tagged_version = ".".join(match.groups())
    configured_version = project_version(pyproject)
    if tagged_version != configured_version:
        raise ValueError(
            f"release tag version {tagged_version} does not match project.version {configured_version}"
        )
    return tagged_version


def write_checksums(output: Path, artifacts: list[Path]) -> None:
    if not artifacts:
        raise ValueError("at least one release artifact is required")
    resolved_output = output.resolve()
    entries: list[tuple[str, Path]] = []
    names: set[str] = set()
    for artifact in artifacts:
        resolved = artifact.resolve()
        if not resolved.is_file():
            raise ValueError(f"release artifact is not a regular file: {artifact}")
        if resolved == resolved_output:
            raise ValueError("checksum manifest cannot include itself")
        name = artifact.name
        if "\n" in name or "\r" in name:
            raise ValueError("release artifact names cannot contain newlines")
        if name in names:
            raise ValueError(f"duplicate release artifact name: {name}")
        names.add(name)
        entries.append((name, resolved))
    lines = []
    for name, artifact in sorted(entries):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and checksum secscan release artifacts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-tag")
    verify.add_argument("tag")
    verify.add_argument("pyproject", type=Path)
    checksums = subparsers.add_parser("checksums")
    checksums.add_argument("output", type=Path)
    checksums.add_argument("artifacts", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        if args.command == "verify-tag":
            print(verify_release_tag(args.tag, args.pyproject))
        else:
            write_checksums(args.output, args.artifacts)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
