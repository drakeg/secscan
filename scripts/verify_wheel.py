from __future__ import annotations

import sys
import zipfile
from pathlib import Path

REQUIRED_FILES = {
    "secscan/__init__.py",
    "secscan/assets.py",
    "secscan/assets_web.py",
    "secscan/aws.py",
    "secscan/aws_ecs.py",
    "secscan/aws_ecs_cli.py",
    "secscan/cli.py",
    "secscan/compare.py",
    "secscan/epss.py",
    "secscan/history.py",
    "secscan/kev.py",
    "secscan/license_policy.py",
    "secscan/models.py",
    "secscan/normalize.py",
    "secscan/policy.py",
    "secscan/public_site.py",
    "secscan/report.py",
    "secscan/service.py",
    "secscan/service_cli.py",
    "secscan/sbom_inventory.py",
    "secscan/sbom_inventory_compare.py",
    "secscan/ssh_credentials.py",
    "secscan/trivy.py",
    "secscan/web.py",
    "secscan/web_assets/__init__.py",
    "secscan/web_assets/index.html",
    "secscan/web_assets/app.js",
    "secscan/web_assets/web_dast.js",
    "secscan/web_assets/linux_host.js",
    "secscan/web_assets/ssh_credentials.js",
    "secscan/web_assets/network.css",
    "secscan/scanners/__init__.py",
    "secscan/scanners/base.py",
    "secscan/scanners/registry.py",
    "secscan/scanners/grype.py",
    "secscan/scanners/image.py",
    "secscan/scanners/filesystem.py",
    "secscan/scanners/full_repository.py",
    "secscan/scanners/linux_host.py",
    "secscan/scanners/network.py",
    "secscan/scanners/repository.py",
    "secscan/scanners/sbom.py",
    "secscan/scanners/web_dast.py",
    "secscan/scanners/windows_host.py",
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
