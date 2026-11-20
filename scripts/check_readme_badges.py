"""Check secscan README badges against verified repository configuration.

No network access, no writes, and no claims based on documentation alone.
Run from any working directory with python scripts/check_readme_badges.py.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
START = "<!-- madmallard-badges:start -->"
END = "<!-- madmallard-badges:end -->"
REPO = "drakeg/secscan"

TECH_SIGNALS = {
    "Python": (ROOT / "pyproject.toml", r"requires-python\s*=\s*\""),
    "FastAPI": (ROOT / "pyproject.toml", r"(?im)^\s*\"fastapi[<>=]"),
    "SQLite": (ROOT / "secscan" / "service.py", r"import sqlite3"),
    "Docker": (ROOT / "Dockerfile", r"(?m)^FROM "),
    "Docker Compose": (ROOT / "compose.yaml", r"(?m)^services:"),
}


def problems(readme: str, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if readme.count(START) != 1 or readme.count(END) != 1:
        return ["README must have exactly one complete badge block"]
    first_h1 = re.search(r"(?m)^# [^\n]+$", readme)
    if first_h1 is None:
        return ["README H1 missing"]
    start, end = readme.index(START), readme.index(END)
    if start < first_h1.end() or end <= start:
        return ["badge block must be immediately after README H1"]
    if readme[first_h1.end():start].strip():
        errors.append("badge block must precede README prose")
    block = readme[start + len(START):end]
    rows = [line for line in block.splitlines() if line.strip()]
    if not 2 <= len(rows) <= 3:
        errors.append("expected two or three compact badge rows")
    manifest = (root / "pyproject.toml").read_text(encoding="utf-8")
    for label, (path, pattern) in TECH_SIGNALS.items():
        local_path = root / path.relative_to(ROOT)
        evidence = local_path.read_text(encoding="utf-8") if local_path.exists() else ""
        if re.search(pattern, evidence) and f"[![{label}]" not in block:
            errors.append(f"verified technology badge missing: {label}")
    if "requires-python = \">=3.12\"" not in manifest and "Python-3.12%2B" in block:
        errors.append("Python version claim no longer matches pyproject.toml")
    for name in ("ci.yml", "codeql.yml", "release.yml"):
        if (root / ".github" / "workflows" / name).exists():
            url = f"https://github.com/{REPO}/actions/workflows/{name}/badge.svg"
            if url not in block:
                errors.append(f"live workflow badge missing: {name}")
    for kind, url in (
        ("issues", f"https://img.shields.io/github/issues/{REPO}"),
        ("pull requests", f"https://img.shields.io/github/issues-pr/{REPO}"),
    ):
        if url not in block:
            errors.append(f"dynamic {kind} badge missing")
    for license_name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        if (root / license_name).is_file():
            if f"https://img.shields.io/github/license/{REPO}" not in block:
                errors.append("license exists but dynamic license badge is missing")
            break
    else:
        if "img.shields.io/github/license/" in block:
            errors.append("license badge cannot be claimed without a license file")
    if "img.shields.io/badge/CI-passing" in block or "img.shields.io/badge/CodeQL-passing" in block:
        errors.append("static successful workflow claims are not permitted")
    if re.search(r"img\.shields\.io/github/v/release/", block):
        errors.append("release badge requires independently verified published release")
    return errors


def main() -> int:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    errors = problems(content)
    if errors:
        for error in errors:
            print(f"README badge error: {error}", file=sys.stderr)
        return 1
    print("README badge evidence validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
