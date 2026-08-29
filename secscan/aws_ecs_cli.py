from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secscan.aws import AwsDiscoveryError
from secscan.aws_ecs import discover_ecs_workloads, load_ecs_config, write_ecs_workloads


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan-ecs",
        description="Discover explicitly approved ECS services and associate immutable workload images",
    )
    parser.add_argument("--config", type=Path, required=True, help="bounded ECS discovery YAML config")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/ecs-workloads.json"),
        help="deterministic ECS workload association evidence",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = discover_ecs_workloads(load_ecs_config(args.config))
        write_ecs_workloads(report, args.output)
    except (AwsDiscoveryError, OSError) as exc:
        print(f"secscan ECS error: {exc}", file=sys.stderr)
        return 1
    print(f"Discovered {report['workload_count']} approved ECS workloads")
    print(f"Association evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
