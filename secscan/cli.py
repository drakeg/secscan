from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import perf_counter

from secscan.aws import (
    AwsDiscoveryError,
    discover_ecr_assets,
    ecr_scan_environment,
    load_ecr_asset,
    load_ecr_assets,
    load_ecr_config,
    validate_ecr_asset,
    write_ecr_assets,
)
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


def _add_history_db_argument(
    parser: argparse.ArgumentParser, *, default: Path | None
) -> None:
    parser.add_argument(
        "--history-db",
        type=Path,
        default=default,
        help="SQLite history database path",
    )


def _add_scan_arguments(parser: argparse.ArgumentParser, target_help: str) -> None:
    parser.add_argument("target", help=target_help)
    parser.add_argument("--output-dir", type=Path, default=Path("/reports"))
    parser.add_argument(
        "--fail-on",
        default=None,
        choices=["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="override the policy severity threshold",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="YAML policy file containing thresholds, suppressions, and rules",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="previous secscan.json report used to classify findings",
    )
    parser.add_argument(
        "--timeout", type=int, default=600, help="scan timeout in seconds"
    )
    _add_history_db_argument(parser, default=None)
    parser.add_argument(
        "--no-history", action="store_true", help="do not record this completed scan"
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
        _add_scan_arguments(target_parser, capability.target_help)

    ecr_scan = scan_subparsers.add_parser(
        "ecr", help="scan one approved ECR image by immutable digest"
    )
    _add_scan_arguments(ecr_scan, "immutable ECR image URI from the inventory")
    ecr_scan.add_argument(
        "--inventory", type=Path, required=True, help="ECR asset inventory JSON"
    )
    ecr_scan.add_argument(
        "--aws-config", type=Path, required=True, help="AWS discovery YAML config"
    )

    history = subparsers.add_parser("history", help="list recorded scans")
    _add_history_db_argument(history, default=Path("/reports/secscan.db"))
    history.add_argument("--limit", type=int, default=20)

    show = subparsers.add_parser("show", help="show one recorded scan")
    show.add_argument("scan_id", type=int)
    _add_history_db_argument(show, default=Path("/reports/secscan.db"))

    discover = subparsers.add_parser("discover", help="discover approved cloud assets")
    discover_subparsers = discover.add_subparsers(dest="discovery_type", required=True)
    ecr = discover_subparsers.add_parser("ecr", help="discover approved Amazon ECR images")
    ecr.add_argument("--config", type=Path, required=True, help="AWS discovery YAML config")
    ecr.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/ecr-assets.json"),
        help="discovered asset inventory path",
    )

    batch = subparsers.add_parser("batch", help="run a bounded batch operation")
    batch_subparsers = batch.add_subparsers(dest="batch_type", required=True)
    ecr_batch = batch_subparsers.add_parser(
        "ecr", help="scan up to 20 explicitly selected ECR image digests"
    )
    ecr_batch.add_argument(
        "--image-uri",
        action="append",
        required=True,
        help="exact immutable URI from the inventory; repeat for each image",
    )
    ecr_batch.add_argument(
        "--inventory", type=Path, required=True, help="ECR asset inventory JSON"
    )
    ecr_batch.add_argument(
        "--aws-config", type=Path, required=True, help="AWS discovery YAML config"
    )
    ecr_batch.add_argument(
        "--output-root", type=Path, default=Path("/reports/ecr-batch")
    )
    ecr_batch.add_argument(
        "--fail-on",
        default=None,
        choices=["NONE", "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    ecr_batch.add_argument("--policy", type=Path)
    ecr_batch.add_argument("--timeout", type=int, default=600)
    _add_history_db_argument(ecr_batch, default=None)
    ecr_batch.add_argument("--no-history", action="store_true")
    return parser


@dataclass(frozen=True)
class BatchEntry:
    image_uri: str
    output_dir: str
    status: str
    exit_code: int


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
    logical_scanner = args.target_type
    scanner_name = logical_scanner
    environment = None
    if logical_scanner == "ecr":
        asset = load_ecr_asset(args.inventory, args.target)
        environment = ecr_scan_environment(load_ecr_config(args.aws_config), asset)
        scanner_name = "image"
    scanner = registry.get(scanner_name)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    baseline_findings = load_baseline(args.baseline) if args.baseline else None
    request = ScanRequest(
        scanner_name=logical_scanner,
        target=args.target,
        timeout_seconds=args.timeout,
        output_dir=args.output_dir,
        environment=environment,
    )
    result = scanner.scan(request)
    scanner_metadata = dict(result.scanner)
    scanner_metadata["secscan_version"] = _secscan_version()
    report_target_type = "container_image" if scanner_name == "image" else logical_scanner
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
        "rule_matches": [
            {
                "rule": matched.rule_index,
                "vulnerability_id": matched.finding.vulnerability_id,
                "package_name": matched.finding.package_name,
                "fail_on": matched.fail_on,
                "reason": matched.reason,
            }
            for matched in evaluation.rule_matches
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
        history_db = args.history_db or (args.output_dir / "secscan.db")
        duration_ms = round((perf_counter() - started) * 1000)
        scan_id = HistoryStore(history_db).record_scan(
            scanner=logical_scanner,
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
        print(f"History: recorded scan {scan_id} in {history_db}")

    print(json.dumps(report["summary"], sort_keys=True))
    print(
        f"Policy: fail_on={fail_on}, "
        f"active={len(evaluation.active_findings)}, "
        f"suppressed={len(evaluation.suppressed_findings)}, "
        f"rules={len(evaluation.rule_matches)}"
    )
    print(f"Artifacts written to {args.output_dir}")
    return (
        2
        if policy_failed(list(evaluation.active_findings), fail_on, policy=policy)
        else 0
    )


def _run_ecr_discovery(args: argparse.Namespace) -> int:
    report = discover_ecr_assets(load_ecr_config(args.config))
    write_ecr_assets(report, args.output)
    print(f"Discovered {report['asset_count']} ECR images")
    print(f"Inventory written to {args.output}")
    return 0


def _run_ecr_batch(args: argparse.Namespace) -> int:
    image_uris = tuple(args.image_uri)
    assets = load_ecr_assets(args.inventory, image_uris)
    config = load_ecr_config(args.aws_config)
    for asset in assets:
        validate_ecr_asset(config, asset)

    if args.output_root.exists() and any(args.output_root.iterdir()):
        raise ValueError("ECR batch output root must be empty")
    args.output_root.mkdir(parents=True, exist_ok=True)
    history_db = args.history_db or (args.output_root / "secscan.db")
    entries: list[BatchEntry] = []
    for index, asset in enumerate(assets, start=1):
        digest_prefix = asset.digest.removeprefix("sha256:")[:12]
        output_dir = args.output_root / f"{index:02d}-{digest_prefix}"
        scan_args = argparse.Namespace(
            target_type="ecr",
            target=asset.image_uri,
            inventory=args.inventory,
            aws_config=args.aws_config,
            output_dir=output_dir,
            fail_on=args.fail_on,
            policy=args.policy,
            baseline=None,
            timeout=args.timeout,
            history_db=history_db,
            no_history=args.no_history,
        )
        try:
            exit_code = _run_scan(scan_args)
            status = "completed" if exit_code == 0 else "policy_failed"
        except (AwsDiscoveryError, TrivyError, OSError, ValueError) as exc:
            print(f"secscan batch error for {asset.image_uri}: {exc}", file=sys.stderr)
            exit_code = 1
            status = "failed"
        entries.append(BatchEntry(asset.image_uri, str(output_dir), status, exit_code))

    batch_exit_code = 1 if any(entry.exit_code == 1 for entry in entries) else 0
    if batch_exit_code == 0 and any(entry.exit_code == 2 for entry in entries):
        batch_exit_code = 2
    manifest = {
        "schema_version": 1,
        "image_count": len(entries),
        "exit_code": batch_exit_code,
        "entries": [asdict(entry) for entry in entries],
    }
    write_json(manifest, args.output_root / "batch.json")
    print(f"Batch manifest written to {args.output_root / 'batch.json'}")
    return batch_exit_code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "history":
            return _run_history(args)
        if args.command == "show":
            return _run_show(args)
        if args.command == "discover" and args.discovery_type == "ecr":
            return _run_ecr_discovery(args)
        if args.command == "batch" and args.batch_type == "ecr":
            return _run_ecr_batch(args)
        return 1
    except (AwsDiscoveryError, TrivyError, OSError, ValueError) as exc:
        print(f"secscan error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
