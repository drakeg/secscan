from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, Protocol

import yaml

from secscan.assets import AssetRecord
from secscan.aws import ACCOUNT_ID_PATTERN, AwsDiscoveryError, REGION_PATTERN

INSTANCE_ID_PATTERN = re.compile(r"^i-[0-9a-f]{8,17}$")
MAX_INSTANCES_PER_TARGET = 50
_ASSOCIATABLE_SCANNERS = {"network", "linux-host", "windows-host"}


class Ec2Client(Protocol):
    def describe_instances(self, **kwargs: object) -> Mapping[str, Any]: ...

    def assume_role(self, **kwargs: str) -> Mapping[str, Any]: ...

    def get_caller_identity(self) -> Mapping[str, Any]: ...


ClientFactory = Callable[[str, str | None, Mapping[str, str] | None], Ec2Client]


@dataclass(frozen=True)
class Ec2Target:
    account_id: str
    region: str
    instance_ids: tuple[str, ...]
    role_arn: str | None = None


@dataclass(frozen=True)
class Ec2DiscoveryConfig:
    targets: tuple[Ec2Target, ...]
    profile: str | None = None


def load_ec2_config(path: Path) -> Ec2DiscoveryConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AwsDiscoveryError(f"could not read EC2 discovery config: {exc}") from exc
    if not isinstance(data, dict):
        raise AwsDiscoveryError("EC2 discovery config must be a mapping")
    profile = data.get("profile")
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise AwsDiscoveryError("profile must be a non-empty string")
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise AwsDiscoveryError("EC2 discovery config must contain at least one target")
    targets = tuple(_parse_target(value) for value in raw_targets)
    identities = [
        (target.account_id, target.region, instance_id)
        for target in targets
        for instance_id in target.instance_ids
    ]
    if len(identities) != len(set(identities)):
        raise AwsDiscoveryError("EC2 instance selections must not contain duplicates")
    return Ec2DiscoveryConfig(targets=targets, profile=profile)


def _parse_target(value: object) -> Ec2Target:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each EC2 target must be a mapping")
    account_id = value.get("account_id")
    region = value.get("region")
    instance_ids = value.get("instance_ids")
    role_arn = value.get("role_arn")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise AwsDiscoveryError("account_id must be a quoted 12-digit AWS account ID")
    if not isinstance(region, str) or not REGION_PATTERN.fullmatch(region):
        raise AwsDiscoveryError("EC2 target region is invalid")
    if not isinstance(instance_ids, list) or not instance_ids:
        raise AwsDiscoveryError("instance_ids must be a non-empty list")
    if len(instance_ids) > MAX_INSTANCES_PER_TARGET:
        raise AwsDiscoveryError(
            f"an EC2 target may contain at most {MAX_INSTANCES_PER_TARGET} instance IDs"
        )
    if not all(isinstance(item, str) and INSTANCE_ID_PATTERN.fullmatch(item) for item in instance_ids):
        raise AwsDiscoveryError("instance_ids contains an invalid EC2 instance ID")
    if len(instance_ids) != len(set(instance_ids)):
        raise AwsDiscoveryError("instance_ids must not contain duplicates")
    if role_arn is not None:
        expected_prefix = f"arn:aws:iam::{account_id}:role/"
        if (
            not isinstance(role_arn, str)
            or not role_arn.startswith(expected_prefix)
            or not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", role_arn)
        ):
            raise AwsDiscoveryError(f"role_arn for account {account_id} is invalid")
    return Ec2Target(account_id, region, tuple(instance_ids), role_arn)


def discover_ec2_assets(
    config: Ec2DiscoveryConfig,
    client_factory: ClientFactory | None = None,
) -> dict[str, object]:
    factory = client_factory or _boto3_client_factory(config.profile)
    assets: list[dict[str, object]] = []
    for target in config.targets:
        credentials = _credentials_for_target(target, factory)
        client = factory("ec2", target.region, credentials)
        try:
            response = client.describe_instances(InstanceIds=list(target.instance_ids))
        except Exception as exc:
            raise AwsDiscoveryError(
                f"EC2 discovery failed for {target.account_id}/{target.region}: {exc}"
            ) from exc
        seen: set[str] = set()
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                asset = _instance_asset(target, instance)
                if asset is not None:
                    seen.add(str(asset["instance_id"]))
                    assets.append(asset)
        missing = sorted(set(target.instance_ids) - seen)
        if missing:
            raise AwsDiscoveryError(
                f"EC2 discovery did not return every approved instance: {', '.join(missing)}"
            )
    assets.sort(key=lambda item: (str(item["account_id"]), str(item["region"]), str(item["instance_id"])))
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "asset_count": len(assets),
        "assets": assets,
    }


def associate_ec2_assets(
    report: dict[str, object],
    secscan_assets: list[AssetRecord],
) -> dict[str, object]:
    raw_assets = report.get("assets")
    if not isinstance(raw_assets, list):
        raise AwsDiscoveryError("EC2 report assets must be a list")
    by_target: dict[str, list[AssetRecord]] = {}
    for asset in secscan_assets:
        if asset.scanner in _ASSOCIATABLE_SCANNERS:
            by_target.setdefault(asset.target, []).append(asset)
    associated = 0
    for value in raw_assets:
        if not isinstance(value, dict):
            raise AwsDiscoveryError("EC2 report contains an invalid asset")
        identities = {
            str(value[name])
            for name in ("private_ip", "public_ip", "private_dns", "public_dns")
            if value.get(name)
        }
        matches = sorted(
            (match for identity in identities for match in by_target.get(identity, [])),
            key=lambda match: (match.scanner, match.target, match.id),
        )
        value["secscan_associations"] = [
            {
                "asset_id": match.id,
                "scanner": match.scanner,
                "target": match.target,
                "latest_job_id": match.latest_job_id,
                "scan_count": match.scan_count,
            }
            for match in matches
        ]
        if matches:
            associated += 1
    report["association_summary"] = {
        "ec2_assets_with_associations": associated,
        "ec2_assets_without_associations": len(raw_assets) - associated,
        "matching": "exact-address-or-dns-target",
    }
    return report


def _instance_asset(target: Ec2Target, instance: Mapping[str, Any]) -> dict[str, object] | None:
    instance_id = instance.get("InstanceId")
    if not isinstance(instance_id, str) or instance_id not in target.instance_ids:
        return None
    launch_time = instance.get("LaunchTime")
    state = instance.get("State") or {}
    return {
        "account_id": target.account_id,
        "region": target.region,
        "instance_id": instance_id,
        "state": str(state.get("Name") or "unknown"),
        "instance_type": str(instance.get("InstanceType") or "unknown"),
        "image_id": str(instance.get("ImageId") or "") or None,
        "platform_details": str(instance.get("PlatformDetails") or "") or None,
        "private_ip": str(instance.get("PrivateIpAddress") or "") or None,
        "public_ip": str(instance.get("PublicIpAddress") or "") or None,
        "private_dns": str(instance.get("PrivateDnsName") or "") or None,
        "public_dns": str(instance.get("PublicDnsName") or "") or None,
        "launch_time": launch_time.isoformat() if isinstance(launch_time, datetime) else None,
    }


def _credentials_for_target(
    target: Ec2Target,
    factory: ClientFactory,
) -> Mapping[str, str] | None:
    if target.role_arn:
        try:
            credentials = factory("sts", None, None).assume_role(
                RoleArn=target.role_arn,
                RoleSessionName="secscan-ec2-discovery",
            )["Credentials"]
            return {
                "aws_access_key_id": str(credentials["AccessKeyId"]),
                "aws_secret_access_key": str(credentials["SecretAccessKey"]),
                "aws_session_token": str(credentials["SessionToken"]),
            }
        except Exception as exc:
            raise AwsDiscoveryError(f"could not assume role for account {target.account_id}: {exc}") from exc
    try:
        caller_account = str(factory("sts", None, None).get_caller_identity()["Account"])
    except Exception as exc:
        raise AwsDiscoveryError(f"could not verify AWS caller identity: {exc}") from exc
    if caller_account != target.account_id:
        raise AwsDiscoveryError(
            f"configured account {target.account_id} does not match caller account {caller_account}"
        )
    return None


def _boto3_client_factory(profile: str | None) -> ClientFactory:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AwsDiscoveryError("EC2 discovery requires the boto3 package") from exc
    session = boto3.Session(profile_name=profile)

    def factory(service: str, region: str | None, credentials: Mapping[str, str] | None) -> Ec2Client:
        kwargs: dict[str, object] = {"region_name": region}
        if credentials:
            kwargs.update(credentials)
        return session.client(service, **kwargs)

    return factory


def write_ec2_assets(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
