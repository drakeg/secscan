from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secscan.aws import AwsDiscoveryError
from secscan.aws_eks import discover_eks_workloads, load_eks_config, write_eks_workloads


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan-eks",
        description="Associate explicitly approved EKS workloads with immutable container images",
    )
    parser.add_argument("--config", type=Path, required=True, help="bounded EKS workload YAML config")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/eks-workloads.json"),
        help="deterministic EKS workload association evidence",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = discover_eks_workloads(load_eks_config(args.config))
        write_eks_workloads(report, args.output)
    except (AwsDiscoveryError, OSError) as exc:
        print(f"secscan EKS error: {exc}", file=sys.stderr)
        return 1
    print(f"Discovered {report['workload_count']} approved EKS workloads")
    print(f"Association evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
