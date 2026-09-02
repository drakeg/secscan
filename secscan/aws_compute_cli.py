from __future__ import annotations

import argparse
from pathlib import Path

from secscan.assets import AssetStore
from secscan.aws import AwsDiscoveryError
from secscan.aws_compute import (
    associate_ec2_assets,
    discover_ec2_assets,
    load_ec2_config,
    write_ec2_assets,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan-ec2",
        description="Discover explicitly approved EC2 instances and associate existing secscan assets",
    )
    parser.add_argument("--config", type=Path, required=True, help="bounded EC2 discovery YAML config")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/reports/ec2-assets.json"),
        help="versioned EC2 inventory output path",
    )
    parser.add_argument(
        "--service-db",
        type=Path,
        help="optional secscan service jobs.db used for exact target association",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = discover_ec2_assets(load_ec2_config(args.config))
        if args.service_db is not None:
            if not args.service_db.is_file():
                raise AwsDiscoveryError(f"secscan service database not found: {args.service_db}")
            report = associate_ec2_assets(report, AssetStore(args.service_db).list(limit=10000))
        write_ec2_assets(report, args.output)
        print(f"Discovered {report['asset_count']} approved EC2 instances")
        if "association_summary" in report:
            print(f"Associations: {report['association_summary']}")
        print(f"Inventory written to {args.output}")
        return 0
    except (AwsDiscoveryError, OSError) as exc:
        print(f"secscan EC2 error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
