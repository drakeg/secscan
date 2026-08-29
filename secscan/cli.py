from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
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
from secscan.history import HistoryStore, ScanHistoryEntry, StoredFinding
from secscan.license_policy import evaluate_license_policy, load_license_policy
from secscan.policy import Policy, evaluate_policy, load_policy, policy_failed
from secscan.report import build_report, write_html, write_json, write_raw_json
from secscan.scanners.base import ScanRequest
from secscan.scanners.registry import build_default_registry
from secscan.sbom_inventory import build_sbom_inventory, write_json_atomic, write_sbom_inventory
from secscan.sbom_inventory_compare import compare_sbom_inventories
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

    trends = subparsers.add_parser("trends", help="summarize scans for one target")
    _add_history_db_argument(trends, default=Path("/reports/secscan.db"))
    trends.add_argument("--scanner", required=True, help="exact recorded scanner name")
    trends.add_argument("--target", required=True, help="exact recorded target")
    trends.add_argument("--limit", type=int, default=20, help="matching scans to include (2-100)")
    trends.add_argument("--output", type=Path, help="write versioned JSON instead of console output")

    finding_changes = subparsers.add_parser(
        "finding-changes", help="compare the two latest finding-level scan records"
    )
    _add_history_db_argument(finding_changes, default=Path("/reports/secscan.db"))
    finding_changes.add_argument("--scanner", required=True, help="exact recorded scanner name")
    finding_changes.add_argument("--target", required=True, help="exact recorded target")
    finding_changes.add_argument("--output", type=Path, help="write versioned JSON evidence")

    finding_timing = subparsers.add_parser(
        "finding-timing", help="summarize bounded finding observation episodes"
    )
    _add_history_db_argument(finding_timing, default=Path("/reports/secscan.db"))
    finding_timing.add_argument("--scanner", required=True, help="exact recorded scanner name")
    finding_timing.add_argument("--target", required=True, help="exact recorded target")
    finding_timing.add_argument(
        "--limit", type=int, default=20, help="finding-enabled scans to include (2-100)"
    )
    finding_timing.add_argument("--output", type=Path, help="write versioned JSON evidence")

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

    inventory = subparsers.add_parser("inventory", help="extract local inventory data")
    inventory_subparsers = inventory.add_subparsers(dest="inventory_type", required=True)
    sbom_inventory = inventory_subparsers.add_parser(
        "sbom", help="normalize packages and declared licenses from an SBOM"
    )
    sbom_inventory.add_argument("target", type=Path, help="CycloneDX or SPDX JSON SBOM")
    sbom_inventory.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/secscan.inventory.json"),
        help="versioned inventory JSON output path",
    )

    compare = subparsers.add_parser("compare", help="compare local secscan artifacts")
    compare_subparsers = compare.add_subparsers(dest="compare_type", required=True)
    inventory_compare = compare_subparsers.add_parser(
        "inventory", help="compare two normalized SBOM inventories"
    )
    inventory_compare.add_argument("baseline", type=Path)
    inventory_compare.add_argument("current", type=Path)
    inventory_compare.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/secscan.inventory.diff.json"),
    )

    check = subparsers.add_parser("check", help="evaluate local artifact policy")
    check_subparsers = check.add_subparsers(dest="check_type", required=True)
    inventory_check = check_subparsers.add_parser(
        "inventory", help="check declared licenses in a normalized inventory"
    )
    inventory_check.add_argument("inventory", type=Path)
    inventory_check.add_argument("--policy", type=Path, required=True)
    inventory_check.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/secscan.inventory.policy.json"),
    )
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


_TREND_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _build_trend(entries: list[ScanHistoryEntry], scanner: str, target: str) -> dict[str, object]:
    if len(entries) < 2:
        raise ValueError(
            f"at least 2 matching scans are required for scanner={scanner!r} target={target!r}"
        )
    oldest = entries[0]
    latest = entries[-1]
    latest_counts = {severity: getattr(latest, severity) for severity in _TREND_SEVERITIES}
    changes = {
        severity: getattr(latest, severity) - getattr(oldest, severity)
        for severity in _TREND_SEVERITIES
    }
    series = [
        {
            "scan_id": entry.id,
            "created_at": entry.created_at,
            "duration_ms": entry.duration_ms,
            "severity": {severity: getattr(entry, severity) for severity in _TREND_SEVERITIES},
        }
        for entry in entries
    ]
    return {
        "schema_version": 1,
        "scanner": scanner,
        "target": target,
        "scan_count": len(entries),
        "oldest_created_at": oldest.created_at,
        "latest_created_at": latest.created_at,
        "latest": latest_counts,
        "change_since_oldest": changes,
        "series": series,
    }


def _write_json_atomic(document: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def _run_trends(args: argparse.Namespace) -> int:
    if not 2 <= args.limit <= 100:
        raise ValueError("trend limit must be between 2 and 100")
    entries = HistoryStore(args.history_db).list_trend_scans(
        scanner=args.scanner, target=args.target, limit=args.limit
    )
    trend = _build_trend(entries, args.scanner, args.target)
    if args.output:
        _write_json_atomic(trend, args.output)
        print(f"Trend written to {args.output}")
        return 0

    print(f"Trend: {args.scanner} {args.target} ({len(entries)} scans)")
    print("ID  Date                 Critical High Medium Low Unknown")
    for entry in entries:
        print(
            f"{entry.id:<3} {entry.created_at:<20} {entry.critical:<8} "
            f"{entry.high:<4} {entry.medium:<6} {entry.low:<3} {entry.unknown}"
        )
    changes = trend["change_since_oldest"]
    assert isinstance(changes, dict)
    print(
        "Change since oldest: "
        + " ".join(f"{severity.upper()}={changes[severity]:+d}" for severity in _TREND_SEVERITIES)
    )
    return 0


def _finding_map(findings: tuple[StoredFinding, ...]) -> dict[str, StoredFinding]:
    return {finding.fingerprint: finding for finding in findings}


def _build_finding_changes(
    observations: list[tuple[ScanHistoryEntry, tuple[StoredFinding, ...]]],
    scanner: str,
    target: str,
) -> dict[str, object]:
    if len(observations) != 2:
        raise ValueError(
            f"2 finding-level scans are required for scanner={scanner!r} target={target!r}"
        )
    previous_scan, previous_findings = observations[0]
    current_scan, current_findings = observations[1]
    previous = _finding_map(previous_findings)
    current = _finding_map(current_findings)
    previous_ids = set(previous)
    current_ids = set(current)

    def documents(ids: set[str], source: dict[str, StoredFinding]) -> list[dict[str, object]]:
        return [asdict(source[fingerprint]) for fingerprint in sorted(ids)]

    new_ids = current_ids - previous_ids
    resolved_ids = previous_ids - current_ids
    unchanged_ids = previous_ids & current_ids
    return {
        "schema_version": 1,
        "scanner": scanner,
        "target": target,
        "previous_scan": {"id": previous_scan.id, "created_at": previous_scan.created_at},
        "current_scan": {"id": current_scan.id, "created_at": current_scan.created_at},
        "summary": {
            "new": len(new_ids),
            "resolved": len(resolved_ids),
            "unchanged": len(unchanged_ids),
        },
        "new": documents(new_ids, current),
        "resolved": documents(resolved_ids, previous),
        "unchanged": documents(unchanged_ids, current),
    }


def _run_finding_changes(args: argparse.Namespace) -> int:
    observations = HistoryStore(args.history_db).latest_finding_observations(
        scanner=args.scanner, target=args.target
    )
    changes = _build_finding_changes(observations, args.scanner, args.target)
    if args.output:
        _write_json_atomic(changes, args.output)
        print(f"Finding changes written to {args.output}")
    else:
        summary = changes["summary"]
        assert isinstance(summary, dict)
        print(
            f"Finding changes: {args.scanner} {args.target} "
            f"new={summary['new']} resolved={summary['resolved']} "
            f"unchanged={summary['unchanged']}"
        )
    return 0


@dataclass
class _OpenFindingEpisode:
    finding: StoredFinding
    first_scan: ScanHistoryEntry
    last_scan: ScanHistoryEntry
    left_censored: bool


def _scan_reference(scan: ScanHistoryEntry) -> dict[str, object]:
    return {"id": scan.id, "created_at": scan.created_at}


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid scan history timestamp: {value}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _episode_document(
    episode: _OpenFindingEpisode, resolved_by: ScanHistoryEntry | None
) -> dict[str, object]:
    observed_seconds: int | None = None
    if resolved_by is not None and not episode.left_censored:
        observed_seconds = round(
            (_timestamp(resolved_by.created_at) - _timestamp(episode.first_scan.created_at)).total_seconds()
        )
        if observed_seconds < 0:
            raise ValueError("finding history timestamps must be chronological")
    return {
        "finding": asdict(episode.finding),
        "first_observed_scan": _scan_reference(episode.first_scan),
        "last_present_scan": _scan_reference(episode.last_scan),
        "resolved_by_scan": _scan_reference(resolved_by) if resolved_by else None,
        "left_censored": episode.left_censored,
        "observed_resolution_seconds": observed_seconds,
    }


def _build_finding_timing(
    observations: list[tuple[ScanHistoryEntry, tuple[StoredFinding, ...]]],
    scanner: str,
    target: str,
) -> dict[str, object]:
    if len(observations) < 2:
        raise ValueError(
            f"at least 2 finding-level scans are required for scanner={scanner!r} target={target!r}"
        )
    timestamps = [_timestamp(scan.created_at) for scan, _ in observations]
    if any(current < previous for previous, current in zip(timestamps, timestamps[1:])):
        raise ValueError("finding history timestamps must be chronological")
    active: dict[str, _OpenFindingEpisode] = {}
    resolved: list[dict[str, object]] = []
    for observation_index, (scan, findings) in enumerate(observations):
        current = _finding_map(findings)
        for fingerprint in sorted(set(active) - set(current)):
            resolved.append(_episode_document(active.pop(fingerprint), scan))
        for fingerprint in sorted(current):
            if fingerprint in active:
                active[fingerprint].finding = current[fingerprint]
                active[fingerprint].last_scan = scan
            else:
                active[fingerprint] = _OpenFindingEpisode(
                    finding=current[fingerprint],
                    first_scan=scan,
                    last_scan=scan,
                    left_censored=observation_index == 0,
                )
    open_episodes = [_episode_document(active[key], None) for key in sorted(active)]
    measurable: list[int] = []
    for episode in resolved:
        value = episode["observed_resolution_seconds"]
        if isinstance(value, int):
            measurable.append(value)
    mean_seconds = round(sum(measurable) / len(measurable), 3) if measurable else None
    return {
        "schema_version": 1,
        "scanner": scanner,
        "target": target,
        "window": {
            "scan_count": len(observations),
            "oldest_scan": _scan_reference(observations[0][0]),
            "latest_scan": _scan_reference(observations[-1][0]),
        },
        "summary": {
            "resolved_episode_count": len(resolved),
            "open_episode_count": len(open_episodes),
            "left_censored_episode_count": sum(
                bool(episode["left_censored"])
                for episode in [*resolved, *open_episodes]
            ),
            "measurable_resolved_count": len(measurable),
            "mean_observed_resolution_seconds": mean_seconds,
        },
        "resolved_episodes": resolved,
        "open_episodes": open_episodes,
    }


def _run_finding_timing(args: argparse.Namespace) -> int:
    if not 2 <= args.limit <= 100:
        raise ValueError("finding timing limit must be between 2 and 100")
    observations = HistoryStore(args.history_db).list_finding_observations(
        scanner=args.scanner, target=args.target, limit=args.limit
    )
    timing = _build_finding_timing(observations, args.scanner, args.target)
    if args.output:
        _write_json_atomic(timing, args.output)
        print(f"Finding timing written to {args.output}")
    else:
        summary = timing["summary"]
        assert isinstance(summary, dict)
        print(
            f"Finding timing: {args.scanner} {args.target} "
            f"resolved={summary['resolved_episode_count']} "
            f"open={summary['open_episode_count']} "
            f"measurable={summary['measurable_resolved_count']} "
            f"mean_observed_seconds={summary['mean_observed_resolution_seconds']}"
        )
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
    report_target_type = "container_image" if scanner_name in {"image", "image-grype"} else logical_scanner
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

    raw_path = args.output_dir / scanner.raw_artifact_name(request)
    report_path = args.output_dir / "secscan.json"
    html_path = args.output_dir / "secscan.html"
    sbom_path = args.output_dir / scanner.sbom_artifact_name(request)
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
            findings=tuple(result.findings),
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


def _run_sbom_inventory(args: argparse.Namespace) -> int:
    inventory = build_sbom_inventory(args.target)
    write_sbom_inventory(inventory, args.output)
    summary = inventory["summary"]
    assert isinstance(summary, dict)
    print(
        f"Inventory: packages={summary['package_count']} "
        f"licensed={summary['packages_with_declared_license']}"
    )
    print(f"Inventory written to {args.output}")
    return 0


def _run_inventory_compare(args: argparse.Namespace) -> int:
    comparison = compare_sbom_inventories(args.baseline, args.current)
    write_json_atomic(comparison, args.output)
    print(f"Inventory comparison: {json.dumps(comparison['summary'], sort_keys=True)}")
    print(f"Comparison written to {args.output}")
    return 0


def _run_inventory_check(args: argparse.Namespace) -> int:
    result = evaluate_license_policy(args.inventory, load_license_policy(args.policy))
    write_json_atomic(result, args.output)
    summary = result["summary"]
    assert isinstance(summary, dict)
    print(f"License policy: {json.dumps(summary, sort_keys=True)}")
    print(f"Policy evidence written to {args.output}")
    return 2 if summary["violation_count"] else 0


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
        if args.command == "trends":
            return _run_trends(args)
        if args.command == "finding-changes":
            return _run_finding_changes(args)
        if args.command == "finding-timing":
            return _run_finding_timing(args)
        if args.command == "discover" and args.discovery_type == "ecr":
            return _run_ecr_discovery(args)
        if args.command == "batch" and args.batch_type == "ecr":
            return _run_ecr_batch(args)
        if args.command == "inventory" and args.inventory_type == "sbom":
            return _run_sbom_inventory(args)
        if args.command == "compare" and args.compare_type == "inventory":
            return _run_inventory_compare(args)
        if args.command == "check" and args.check_type == "inventory":
            return _run_inventory_check(args)
        return 1
    except (AwsDiscoveryError, TrivyError, OSError, ValueError) as exc:
        print(f"secscan error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
