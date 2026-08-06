from __future__ import annotations

from pathlib import Path

import argparse
import json

import pytest

from secscan.aws import EcrAccount, EcrAsset, EcrDiscoveryConfig
from secscan.cli import _run_ecr_batch, build_parser
from secscan.trivy import TrivyError


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


def test_ecr_batch_parser_accepts_repeated_exact_uris() -> None:
    args = build_parser().parse_args(
        [
            "batch",
            "ecr",
            "--image-uri",
            "first",
            "--image-uri",
            "second",
            "--inventory",
            "inventory.json",
            "--aws-config",
            "aws.yaml",
        ]
    )

    assert args.batch_type == "ecr"
    assert args.image_uri == ["first", "second"]


def test_ecr_batch_aggregates_exit_codes_and_isolates_outputs(tmp_path: Path, monkeypatch) -> None:
    assets = (
        EcrAsset("123456789012", "us-east-1", "one", f"sha256:{'a' * 64}", "uri-one"),
        EcrAsset("123456789012", "us-east-1", "two", f"sha256:{'b' * 64}", "uri-two"),
    )
    config = EcrDiscoveryConfig((EcrAccount("123456789012", ("us-east-1",), ("one", "two")),))
    monkeypatch.setattr("secscan.cli.load_ecr_assets", lambda *_args: assets)
    monkeypatch.setattr("secscan.cli.load_ecr_config", lambda _path: config)
    monkeypatch.setattr("secscan.cli.validate_ecr_asset", lambda *_args: None)
    exit_codes = iter((0, 2))
    output_dirs: list[Path] = []

    def fake_scan(scan_args: argparse.Namespace) -> int:
        output_dirs.append(scan_args.output_dir)
        return next(exit_codes)

    monkeypatch.setattr("secscan.cli._run_scan", fake_scan)
    output_root = tmp_path / "batch"
    args = argparse.Namespace(
        image_uri=["uri-one", "uri-two"],
        inventory=tmp_path / "inventory.json",
        aws_config=tmp_path / "aws.yaml",
        output_root=output_root,
        history_db=None,
        fail_on="HIGH",
        policy=None,
        timeout=600,
        no_history=False,
    )

    assert _run_ecr_batch(args) == 2
    manifest = json.loads((output_root / "batch.json").read_text(encoding="utf-8"))
    assert manifest["exit_code"] == 2
    assert [entry["status"] for entry in manifest["entries"]] == [
        "completed",
        "policy_failed",
    ]
    assert output_dirs == [
        output_root / f"01-{'a' * 12}",
        output_root / f"02-{'b' * 12}",
    ]


def test_ecr_batch_continues_after_operational_failure(tmp_path: Path, monkeypatch) -> None:
    assets = (
        EcrAsset("123456789012", "us-east-1", "one", f"sha256:{'a' * 64}", "uri-one"),
        EcrAsset("123456789012", "us-east-1", "two", f"sha256:{'b' * 64}", "uri-two"),
    )
    monkeypatch.setattr("secscan.cli.load_ecr_assets", lambda *_args: assets)
    monkeypatch.setattr("secscan.cli.load_ecr_config", lambda _path: EcrDiscoveryConfig(()))
    monkeypatch.setattr("secscan.cli.validate_ecr_asset", lambda *_args: None)
    calls = 0

    def fake_scan(_scan_args: argparse.Namespace) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TrivyError("scan failed")
        return 0

    monkeypatch.setattr("secscan.cli._run_scan", fake_scan)
    output_root = tmp_path / "batch"
    args = argparse.Namespace(
        image_uri=["uri-one", "uri-two"],
        inventory=tmp_path / "inventory.json",
        aws_config=tmp_path / "aws.yaml",
        output_root=output_root,
        history_db=None,
        fail_on=None,
        policy=None,
        timeout=600,
        no_history=True,
    )

    assert _run_ecr_batch(args) == 1
    manifest = json.loads((output_root / "batch.json").read_text(encoding="utf-8"))
    assert [entry["status"] for entry in manifest["entries"]] == ["failed", "completed"]


def test_ecr_batch_rejects_nonempty_output_root(tmp_path: Path, monkeypatch) -> None:
    asset = EcrAsset("123456789012", "us-east-1", "app", f"sha256:{'a' * 64}", "uri")
    monkeypatch.setattr("secscan.cli.load_ecr_assets", lambda *_args: (asset,))
    monkeypatch.setattr("secscan.cli.load_ecr_config", lambda _path: EcrDiscoveryConfig(()))
    monkeypatch.setattr("secscan.cli.validate_ecr_asset", lambda *_args: None)
    output_root = tmp_path / "batch"
    output_root.mkdir()
    (output_root / "existing.txt").write_text("keep", encoding="utf-8")
    args = argparse.Namespace(
        image_uri=["uri"],
        inventory=tmp_path / "inventory.json",
        aws_config=tmp_path / "aws.yaml",
        output_root=output_root,
        history_db=None,
        fail_on=None,
        policy=None,
        timeout=600,
        no_history=True,
    )

    with pytest.raises(ValueError, match="must be empty"):
        _run_ecr_batch(args)
    assert (output_root / "existing.txt").read_text(encoding="utf-8") == "keep"
