from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Protocol

import yaml

ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]+$")
REPOSITORY_PATTERN = re.compile(r"^(?![./])[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
INSTANCE_ID_PATTERN = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")
MAX_ECR_BATCH_IMAGES = 20
MAX_EC2_INSTANCES_PER_ACCOUNT = 100


class AwsDiscoveryError(RuntimeError):
    pass


class AwsClient(Protocol):
    def get_paginator(self, operation_name: str) -> Any: ...

    def assume_role(self, **kwargs: str) -> Mapping[str, Any]: ...

    def get_caller_identity(self) -> Mapping[str, Any]: ...


ClientFactory = Callable[[str, str | None, Mapping[str, str] | None], AwsClient]


@dataclass(frozen=True)
class EcrAccount:
    account_id: str
    regions: tuple[str, ...]
    repositories: tuple[str, ...]
    instances: tuple[str, ...] = ()
    role_arn: str | None = None


@dataclass(frozen=True)
class EcrDiscoveryConfig:
    accounts: tuple[EcrAccount, ...]
    profile: str | None = None


@dataclass(frozen=True)
class EcrAsset:
    account_id: str
    region: str
    repository: str
    digest: str
    image_uri: str


def load_ecr_config(path: Path) -> EcrDiscoveryConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AwsDiscoveryError(f"could not read AWS discovery config: {exc}") from exc
    if not isinstance(data, dict):
        raise AwsDiscoveryError("AWS discovery config must be a mapping")
    raw_accounts = data.get("accounts")
    if not isinstance(raw_accounts, list) or not raw_accounts:
        raise AwsDiscoveryError("AWS discovery config must contain at least one account")
    profile = data.get("profile")
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise AwsDiscoveryError("profile must be a non-empty string")
    accounts = tuple(_parse_account(item) for item in raw_accounts)
    if len({account.account_id for account in accounts}) != len(accounts):
        raise AwsDiscoveryError("account IDs must not contain duplicates")
    return EcrDiscoveryConfig(accounts=accounts, profile=profile)


def load_ecr_asset(inventory_path: Path, image_uri: str) -> EcrAsset:
    return load_ecr_assets(inventory_path, (image_uri,))[0]


def load_ecr_assets(inventory_path: Path, image_uris: tuple[str, ...]) -> tuple[EcrAsset, ...]:
    if not image_uris:
        raise AwsDiscoveryError("at least one ECR image URI must be selected")
    if len(image_uris) > MAX_ECR_BATCH_IMAGES:
        raise AwsDiscoveryError(f"ECR batch selection exceeds the limit of {MAX_ECR_BATCH_IMAGES} images")
    if len(set(image_uris)) != len(image_uris):
        raise AwsDiscoveryError("ECR image URI selections must not contain duplicates")
    try:
        data = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AwsDiscoveryError(f"could not read ECR inventory: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise AwsDiscoveryError("ECR inventory must use schema version 1")
    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list):
        raise AwsDiscoveryError("ECR inventory assets must be a list")
    assets: dict[str, EcrAsset] = {}
    for value in raw_assets:
        asset = _parse_asset(value)
        if asset.image_uri in assets:
            raise AwsDiscoveryError("an image URI appears more than once in the ECR inventory")
        assets[asset.image_uri] = asset
    missing = [image_uri for image_uri in image_uris if image_uri not in assets]
    if missing:
        raise AwsDiscoveryError("a requested image URI is not present in the ECR inventory")
    return tuple(assets[image_uri] for image_uri in image_uris)


def _parse_asset(value: object) -> EcrAsset:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each ECR inventory asset must be a mapping")
    account_id = value.get("account_id")
    region = value.get("region")
    repository = value.get("repository")
    digest = value.get("digest")
    image_uri = value.get("image_uri")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise AwsDiscoveryError("ECR inventory contains an invalid account ID")
    if not isinstance(region, str) or not REGION_PATTERN.fullmatch(region):
        raise AwsDiscoveryError("ECR inventory contains an invalid region")
    if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
        raise AwsDiscoveryError("ECR inventory contains an invalid repository")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise AwsDiscoveryError("ECR inventory contains an invalid image digest")
    expected_uri = f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository}@{digest}"
    if image_uri != expected_uri:
        raise AwsDiscoveryError("ECR inventory contains an inconsistent image URI")
    return EcrAsset(account_id, region, repository, digest, expected_uri)


def ecr_scan_environment(config: EcrDiscoveryConfig, asset: EcrAsset, client_factory: ClientFactory | None = None) -> dict[str, str]:
    account = validate_ecr_asset(config, asset)
    factory = client_factory or _boto3_client_factory(config.profile)
    credentials = _credentials_for_account(account, factory, "secscan-ecr-scan")
    environment = {"AWS_REGION": asset.region, "AWS_DEFAULT_REGION": asset.region}
    if credentials:
        environment.update({
            "AWS_ACCESS_KEY_ID": credentials["aws_access_key_id"],
            "AWS_SECRET_ACCESS_KEY": credentials["aws_secret_access_key"],
            "AWS_SESSION_TOKEN": credentials["aws_session_token"],
        })
    elif config.profile:
        environment["AWS_PROFILE"] = config.profile
    return environment


def validate_ecr_asset(config: EcrDiscoveryConfig, asset: EcrAsset) -> EcrAccount:
    account = next((candidate for candidate in config.accounts if candidate.account_id == asset.account_id), None)
    if account is None:
        raise AwsDiscoveryError("inventory account is not approved by the AWS config")
    if asset.region not in account.regions:
        raise AwsDiscoveryError("inventory region is not approved by the AWS config")
    if asset.repository not in account.repositories:
        raise AwsDiscoveryError("inventory repository is not approved by the AWS config")
    return account


def _parse_account(value: object) -> EcrAccount:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each AWS account entry must be a mapping")
    account_id = value.get("account_id")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise AwsDiscoveryError("account_id must be a quoted 12-digit AWS account ID")
    regions = _validated_strings(value.get("regions"), "regions", REGION_PATTERN)
    repositories = _validated_strings(value.get("repositories"), "repositories", REPOSITORY_PATTERN, allow_empty=True)
    instances = _validated_strings(value.get("instances"), "instances", INSTANCE_ID_PATTERN, allow_empty=True)
    if len(instances) > MAX_EC2_INSTANCES_PER_ACCOUNT:
        raise AwsDiscoveryError(f"instances exceeds the limit of {MAX_EC2_INSTANCES_PER_ACCOUNT} per account")
    if not repositories and not instances:
        raise AwsDiscoveryError("each AWS account must approve at least one repository or instance")
    role_arn = value.get("role_arn")
    if role_arn is not None:
        expected_prefix = f"arn:aws:iam::{account_id}:role/"
        if not isinstance(role_arn, str) or not role_arn.startswith(expected_prefix) or not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", role_arn):
            raise AwsDiscoveryError(f"role_arn for account {account_id} is invalid")
    return EcrAccount(account_id, regions, repositories, instances, role_arn)


def _validated_strings(value: object, name: str, pattern: re.Pattern[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    if value is None and allow_empty:
        return ()
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise AwsDiscoveryError(f"{name} must be {qualifier}")
    if not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        raise AwsDiscoveryError(f"{name} contains an invalid value")
    if len(set(value)) != len(value):
        raise AwsDiscoveryError(f"{name} must not contain duplicates")
    return tuple(value)


def discover_ecr_assets(config: EcrDiscoveryConfig, client_factory: ClientFactory | None = None) -> dict[str, object]:
    factory = client_factory or _boto3_client_factory(config.profile)
    assets: list[dict[str, object]] = []
    for account in config.accounts:
        if not account.repositories:
            continue
        credentials = _credentials_for_account(account, factory, "secscan-ecr-discovery")
        for region in account.regions:
            client = factory("ecr", region, credentials)
            paginator = client.get_paginator("describe_images")
            for repository in account.repositories:
                try:
                    pages = paginator.paginate(registryId=account.account_id, repositoryName=repository, filter={"tagStatus": "ANY"})
                    for page in pages:
                        for image in page.get("imageDetails", []):
                            asset = _image_asset(account.account_id, region, repository, image)
                            if asset is not None:
                                assets.append(asset)
                except Exception as exc:
                    raise AwsDiscoveryError(f"ECR discovery failed for {account.account_id}/{region}/{repository}: {exc}") from exc
    assets.sort(key=lambda item: (str(item["account_id"]), str(item["region"]), str(item["repository"]), str(item["digest"])))
    return {"schema_version": 1, "generated_at": datetime.now(UTC).isoformat(), "asset_count": len(assets), "assets": assets}


def discover_ec2_assets(config: EcrDiscoveryConfig, client_factory: ClientFactory | None = None) -> dict[str, object]:
    factory = client_factory or _boto3_client_factory(config.profile)
    assets: list[dict[str, object]] = []
    for account in config.accounts:
        if not account.instances:
            continue
        credentials = _credentials_for_account(account, factory, "secscan-ec2-discovery")
        expected = set(account.instances)
        found: set[str] = set()
        for region in account.regions:
            client = factory("ec2", region, credentials)
            paginator = client.get_paginator("describe_instances")
            try:
                pages = paginator.paginate(InstanceIds=list(account.instances))
                for page in pages:
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            asset = _instance_asset(account.account_id, region, instance)
                            instance_id = str(asset["instance_id"])
                            if instance_id not in expected:
                                raise AwsDiscoveryError("EC2 returned an instance outside the configured allow-list")
                            found.add(instance_id)
                            assets.append(asset)
            except AwsDiscoveryError:
                raise
            except Exception as exc:
                raise AwsDiscoveryError(f"EC2 discovery failed for {account.account_id}/{region}: {exc}") from exc
        missing = sorted(expected - found)
        if missing:
            raise AwsDiscoveryError(f"approved EC2 instances were not found in configured regions: {', '.join(missing)}")
    assets.sort(key=lambda item: (str(item["account_id"]), str(item["region"]), str(item["instance_id"])))
    return {"schema_version": 1, "generated_at": datetime.now(UTC).isoformat(), "asset_count": len(assets), "assets": assets}


def _credentials_for_account(account: EcrAccount, factory: ClientFactory, session_name: str) -> Mapping[str, str] | None:
    if account.role_arn:
        try:
            response = factory("sts", None, None).assume_role(RoleArn=account.role_arn, RoleSessionName=session_name)
            credentials = response["Credentials"]
            return {
                "aws_access_key_id": credentials["AccessKeyId"],
                "aws_secret_access_key": credentials["SecretAccessKey"],
                "aws_session_token": credentials["SessionToken"],
            }
        except Exception as exc:
            raise AwsDiscoveryError(f"could not assume role for account {account.account_id}: {exc}") from exc
    try:
        caller_account = str(factory("sts", None, None).get_caller_identity()["Account"])
    except Exception as exc:
        raise AwsDiscoveryError(f"could not verify AWS caller identity: {exc}") from exc
    if caller_account != account.account_id:
        raise AwsDiscoveryError(f"configured account {account.account_id} does not match caller account {caller_account}")
    return None


def _image_asset(account_id: str, region: str, repository: str, image: Mapping[str, Any]) -> dict[str, object] | None:
    digest = image.get("imageDigest")
    if not isinstance(digest, str):
        return None
    pushed_at = image.get("imagePushedAt")
    return {
        "account_id": account_id,
        "region": region,
        "repository": repository,
        "digest": digest,
        "tags": sorted(str(tag) for tag in (image.get("imageTags") or [])),
        "size_bytes": int(image.get("imageSizeInBytes", 0)),
        "pushed_at": pushed_at.isoformat() if isinstance(pushed_at, datetime) else None,
        "image_uri": f"{account_id}.dkr.ecr.{region}.amazonaws.com/{repository}@{digest}",
    }


def _literal_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _instance_asset(account_id: str, region: str, instance: Mapping[str, Any]) -> dict[str, object]:
    instance_id = instance.get("InstanceId")
    if not isinstance(instance_id, str) or not INSTANCE_ID_PATTERN.fullmatch(instance_id):
        raise AwsDiscoveryError("EC2 returned an invalid instance ID")
    private_ip = _literal_ip(instance.get("PrivateIpAddress"))
    public_ip = _literal_ip(instance.get("PublicIpAddress"))
    candidate_targets = sorted({value for value in (private_ip, public_ip) if value})
    launch_time = instance.get("LaunchTime")
    tags = sorted(
        ({"key": str(tag.get("Key", "")), "value": str(tag.get("Value", ""))} for tag in (instance.get("Tags") or []) if isinstance(tag, Mapping)),
        key=lambda tag: (tag["key"], tag["value"]),
    )
    return {
        "account_id": account_id,
        "region": region,
        "instance_id": instance_id,
        "state": str((instance.get("State") or {}).get("Name") or "unknown"),
        "platform": str(instance.get("Platform") or "linux/unix"),
        "platform_details": str(instance.get("PlatformDetails") or ""),
        "private_ip": private_ip,
        "public_ip": public_ip,
        "private_dns": str(instance.get("PrivateDnsName") or ""),
        "public_dns": str(instance.get("PublicDnsName") or ""),
        "vpc_id": str(instance.get("VpcId") or ""),
        "subnet_id": str(instance.get("SubnetId") or ""),
        "launch_time": launch_time.isoformat() if isinstance(launch_time, datetime) else None,
        "tags": tags,
        "candidate_targets": candidate_targets,
    }


def _boto3_client_factory(profile: str | None) -> ClientFactory:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AwsDiscoveryError("AWS discovery requires the boto3 package") from exc
    session = boto3.Session(profile_name=profile)

    def factory(service: str, region: str | None, credentials: Mapping[str, str] | None) -> AwsClient:
        kwargs: dict[str, object] = {"region_name": region}
        if credentials:
            kwargs.update(credentials)
        return session.client(service, **kwargs)

    return factory


def _write_assets(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_ecr_assets(report: dict[str, object], output: Path) -> None:
    _write_assets(report, output)


def write_ec2_assets(report: dict[str, object], output: Path) -> None:
    _write_assets(report, output)
