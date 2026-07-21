from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from secscan import __version__
from secscan.normalize import normalize_trivy
from secscan.policy import policy_failed
from secscan.report import build_report, write_json
from secscan.trivy import TrivyError, scan_image


def _trivy_version() -> str:
    try:
        completed = subprocess.run(
            ["trivy", "--version"], check=False, capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"
    return (completed.stdout or completed.stderr).strip().splitlines()[0] or "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan", description="Scan container images with normalized output"
    )
    parser.add_argument("--version", action="version", version=f"secscan {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a target")
    scan_subparsers = scan.add_subparsers(dest="target_type", required=True)
    image = scan_subparsers.add_parser("image", help="scan a container image")
    image.add_argument("image", help="image reference, for example alpine:3.20")
    image.add_argument("--output", type=Path, default=Path("/reports/secscan.json"))
    image.add_argument(
        "--fail-on",
        default="CRITICAL",
        choices=["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="return exit code 2 when findings meet or exceed this severity",
    )
    image.add_argument("--timeout", type=int, default=600, help="scan timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan" and args.target_type == "image":
        try:
            raw = scan_image(args.image, timeout_seconds=args.timeout)
            findings = normalize_trivy(raw)
            report = build_report(
                args.image,
                findings,
                {
                    "name": "trivy",
                    "version": _trivy_version(),
                    "secscan_version": __version__,
                },
            )
            write_json(report, args.output)
            print(json.dumps(report["summary"], sort_keys=True))
            print(f"Report written to {args.output}")
            return 2 if policy_failed(findings, args.fail_on) else 0
        except (TrivyError, OSError, ValueError) as exc:
            print(f"secscan error: {exc}", file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
