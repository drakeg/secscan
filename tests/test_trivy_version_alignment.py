"""Keep the Trivy version used by Docker build, CI and local container preflight aligned."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_trivy_container_version_consistent_across_build_and_preflights() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")

    build = re.search(r"(?m)^FROM aquasec/trivy:(\d+\.\d+\.\d+) AS trivy$", dockerfile)
    ci = re.search(r"aquasec/trivy:(\d+\.\d+\.\d+) image", workflow)
    local = re.search(r"aquasec/trivy:(\d+\.\d+\.\d+) image", script)
    assert build is not None, "Dockerfile must pin the Trivy image"
    assert ci is not None, "CI must pin the Trivy image"
    assert local is not None, "local container preflight must pin the Trivy image"
    assert build.group(1) == ci.group(1) == local.group(1), "Trivy versions drifted"
