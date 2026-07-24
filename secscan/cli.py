from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import perf_counter

from secscan.compare import compare_findings, load_baseline
from secscan.history import HistoryStore, ScanHistoryEntry
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


def _add_history_db_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--history-db",
        type=Path,
        default=Path("/reports/secscan.db"),
        help="SQLite history database path",
    )


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
        _add_history_db_argument(target_parser)
        target_parser.add_argument(
            "--no-history", action="store_true", help="do not record this completed scan"
        )

    history = subparsers.add_parser("history", help="list recorded scans")
    _add_history_db_argument(history)
    history.add_argument("--limit", type=int, default=20)

    show = subparsers.add_parser("show", help="show one recorded scan")
    show.add_argument("scan_id", type=int)
    _add_history_db_argument(show)
    return parser


def _print_history_entry(entry: ScanHistoryEntry) -> None:
    print(f"ID: {entry.id}")
    print(f"Date: {entry.created_at}")
    print(f"Scanner: {entry.scanner}")
    print(f"Target: {entry.target}")
    print(f"Duration: {entry.duration_ms} ms")
    print(f"Policy threshold: {entry.fail_on}")
    print(
        "Severity: "
        f"CRITICAL={entry.critical} HIGH={entry.high} MEDIUM={entry.medium} "
        f"LOW={entry.low} UNKNOWN={entry.unknown}"
    )
    print(f"Report: {entry.report_path}")
    print(f"SBOM: {entry.sbom_path}")
    if entry.diff_path:
        print(f"Diff: {entry.diff_path}")
    print(f"secscan: {entry.secscan_version}")
    print(f"Scanner engine: {entry.scanner_version}")


def _run_history(args: argparse.Namespace) -> int:
    entries = HistoryStore(args.history_db).list_scans(args.limit)
    print("ID  Date                 Scanner      Critical High Medium Target")
    for entry in entries:
        print(
            f"{entry.id:<3} {entry.created_at:<20} {entry.scanner:<12} "
            f"{entry.critical:<8} {entry.high:<4} {entry.medium:<6} {entry.target}"
        )
    return 0


def _run_show(args: argparse.Namespace) -> int:
    entry = HistoryStore(args.history_db).get_scan(args.scan_id)
    if entry is None:
        raise ValueError(f"scan history entry not found: {args.scan_id}")
    _print_history_entry(entry)
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    started = perf_counter()
    registry = build_default_registry()
    scanner = registry.get(args.target_type)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    baseline_findings = load_baseline(args.baseline) if args.baseline else None
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

    raw_path = args.output_dir / "trivy.json"
    report_path = args.output_dir / "secscan.json"
    html_path = args.output_dir / "secscan.html"
    sbom_path = args.output_dir / "secscan.cdx.json"
    diff_path: Path | None = None

    write_raw_json(result.raw, raw_path)
    write_json(report, report_path)
    write_html(report, html_path)
    scanner.generate_sbom(request, sbom_path)

    if baseline_findings is not None:
        comparison = compare_findings(list(result.findings), baseline_findings)
        diff_path = args.output_dir / "secscan.diff.json"
        write_json(comparison, diff_path)
        print(f"Comparison: {json.dumps(comparison['summary'], sort_keys=True)}")

    if not args.no_history:
        duration_ms = round((perf_counter() - started) * 1000)
        scan_id = HistoryStore(args.history_db).record_scan(
            scanner=args.target_type,
            target=args.target,
            duration_ms=duration_ms,
            fail_on=fail_on,
            summary=report["summary"],
            report_path=report_path,
            sbom_path=sbom_path,
            diff_path=diff_path,
            secscan_version=_secscan_version(),
            scanner_version=str(scanner_metadata.get("version", "unknown")),
        )
        print(f"History: recorded scan {scan_id} in {args.history_db}")

    print(json.dumps(report["summary"], sort_keys=True))
    print(
        f"Policy: fail_on={fail_on}, "
        f"active={len(evaluation.active_findings)}, "
        f"suppressed={len(evaluation.suppressed_findings)}"
    )
    print(f"Artifacts written to {args.output_dir}")
    return 2 if policy_failed(list(evaluation.active_findings), fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "history":
            return _run_history(args)
        if args.command == "show":
            return _run_show(args)
        return 1
    except (TrivyError, OSError, ValueError) as exc:
        print(f"secscan error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
