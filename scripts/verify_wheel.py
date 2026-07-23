from __future__ import annotations

import sys
import zipfile
from pathlib import Path

REQUIRED_FILES = {
    "secscan/__init__.py",
    "secscan/cli.py",
    "secscan/models.py",
    "secscan/normalize.py",
    "secscan/policy.py",
    "secscan/report.py",
    "secscan/trivy.py",
    "secscan/scanners/__init__.py",
    "secscan/scanners/base.py",
    "secscan/scanners/registry.py",
    "secscan/scanners/image.py",
    "secscan/scanners/filesystem.py",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_wheel.py <wheel>", file=sys.stderr)
        return 2

    wheel = Path(sys.argv[1])
    if not wheel.is_file():
        print(f"wheel not found: {wheel}", file=sys.stderr)
        return 2

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    package_files = sorted(name for name in names if name.startswith("secscan/"))
    print(f"wheel package contents for {wheel.name}:")
    for name in package_files:
        print(f"- {name}")

    missing = sorted(REQUIRED_FILES - names)
    if missing:
        print("wheel is missing required secscan modules:", file=sys.stderr)
        for name in missing:
            print(f"- {name}", file=sys.stderr)
        return 1

    print(f"verified {wheel.name}: {len(REQUIRED_FILES)} required modules present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
