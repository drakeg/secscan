from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from secscan.compare import compare_findings, load_baseline
from secscan.policy import Policy, evaluate_policy, load_policy, policy_failed
from secscan.report import build_report, write_html, write_json, write_raw_json
from secscan.scanners.base import ScanRequest
from secscan.scanners.registry import build_default_registry
from secscan.trivy import TrivyError


def _secscan_version() -> str:
    try:
        return version("secscan")
    except PackageNotFoundError:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    registry = build_default_registry()
    parser = argparse.ArgumentParser(
        prog="secscan", description="Scan targets with normalized output"
    )
    parser.add_argument("--version", action="version", version=f"secscan {_secscan_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a target")
    scan_subparsers = scan.add_subparsers(dest="target_type", required=True)
    for capability in registry.capabilities():
        target_parser = scan_subparsers.add_parser(
            capability.name, help=capability.description
        )
        target_parser.add_argument("target", help=capability.target_help)
        target_parser.add_argument("--output-dir", type=Path, default=Path("/reports"))
        target_parser.add_argument(
            "--fail-on",
            default=None,
            choices=["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            help="override the policy severity threshold",
        )
        target_parser.add_argument(
            "--policy",
            type=Path,
            help="YAML policy file containing a threshold and suppressions",
        )
        target_parser.add_argument(
            "--baseline",
            type=Path,
            help="previous secscan.json report used to classify findings",
        )
        target_parser.add_argument(
            "--timeout", type=int, default=600, help="scan timeout in seconds"
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 1

    try:
        registry = build_default_registry()
        scanner = registry.get(args.target_type)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        request = ScanRequest(
            scanner_name=args.target_type,
            target=args.target,
            timeout_seconds=args.timeout,
            output_dir=args.output_dir,
        )
        result = scanner.scan(request)
        scanner_metadata = dict(result.scanner)
        scanner_metadata["secscan_version"] = _secscan_version()
        report_target_type = "container_image" if args.target_type == "image" else args.target_type
        report = build_report(
            args.target,
            list(result.findings),
            scanner_metadata,
            target_type=report_target_type,
        )

        policy = load_policy(args.policy) if args.policy else Policy()
        fail_on = args.fail_on or policy.fail_on
        evaluation = evaluate_policy(list(result.findings), policy)
        report["policy"] = {
            "fail_on": fail_on,
            "active_findings": len(evaluation.active_findings),
            "suppressed_findings": [
                {
                    "vulnerability_id": suppressed.finding.vulnerability_id,
                    "package_name": suppressed.finding.package_name,
                    "reason": suppressed.reason,
                    "expires": suppressed.expires.isoformat(),
                }
                for suppressed in evaluation.suppressed_findings
            ],
        }

        write_raw_json(result.raw, args.output_dir / "trivy.json")
        write_json(report, args.output_dir / "secscan.json")
        write_html(report, args.output_dir / "secscan.html")
        scanner.generate_sbom(request, args.output_dir / "secscan.cdx.json")

        if args.baseline:
            comparison = compare_findings(list(result.findings), load_baseline(args.baseline))
            write_json(comparison, args.output_dir / "secscan.diff.json")
            print(f"Comparison: {json.dumps(comparison['summary'], sort_keys=True)}")

        print(json.dumps(report["summary"], sort_keys=True))
        print(
            f"Policy: fail_on={fail_on}, "
            f"active={len(evaluation.active_findings)}, "
            f"suppressed={len(evaluation.suppressed_findings)}"
        )
        print(f"Artifacts written to {args.output_dir}")
        return 2 if policy_failed(list(evaluation.active_findings), fail_on) else 0
    except (TrivyError, OSError, ValueError) as exc:
        print(f"secscan error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
