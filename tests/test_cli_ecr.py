from __future__ import annotations

from pathlib import Path

from secscan.cli import build_parser


def test_ecr_scan_requires_inventory_and_aws_config() -> None:
    args = build_parser().parse_args(
        [
            "scan",
            "ecr",
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:digest",
            "--inventory",
            "inventory.json",
            "--aws-config",
            "aws.yaml",
            "--output-dir",
            "reports",
        ]
    )

    assert args.target_type == "ecr"
    assert args.inventory == Path("inventory.json")
    assert args.aws_config == Path("aws.yaml")
    assert args.output_dir == Path("reports")
