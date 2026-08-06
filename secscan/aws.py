from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, Protocol

import yaml

ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]+$")
REPOSITORY_PATTERN = re.compile(r"^(?![./])[a-z0-9]+(?:[._/-][a-z0-9]+)*$")


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
    try:
        data = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AwsDiscoveryError(f"could not read ECR inventory: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise AwsDiscoveryError("ECR inventory must use schema version 1")
    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list):
        raise AwsDiscoveryError("ECR inventory assets must be a list")
    matches: list[EcrAsset] = []
    for value in raw_assets:
        asset = _parse_asset(value)
        if asset.image_uri == image_uri:
            matches.append(asset)
    if not matches:
        raise AwsDiscoveryError("requested image URI is not present in the ECR inventory")
    if len(matches) > 1:
        raise AwsDiscoveryError("requested image URI appears more than once in the ECR inventory")
    return matches[0]


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


def ecr_scan_environment(
    config: EcrDiscoveryConfig,
    asset: EcrAsset,
    client_factory: ClientFactory | None = None,
) -> dict[str, str]:
    account = next(
        (candidate for candidate in config.accounts if candidate.account_id == asset.account_id),
        None,
    )
    if account is None:
        raise AwsDiscoveryError("inventory account is not approved by the AWS config")
    if asset.region not in account.regions:
        raise AwsDiscoveryError("inventory region is not approved by the AWS config")
    if asset.repository not in account.repositories:
        raise AwsDiscoveryError("inventory repository is not approved by the AWS config")
    factory = client_factory or _boto3_client_factory(config.profile)
    credentials = _credentials_for_account(account, factory)
    environment = {"AWS_REGION": asset.region, "AWS_DEFAULT_REGION": asset.region}
    if credentials:
        environment.update(
            {
                "AWS_ACCESS_KEY_ID": credentials["aws_access_key_id"],
                "AWS_SECRET_ACCESS_KEY": credentials["aws_secret_access_key"],
                "AWS_SESSION_TOKEN": credentials["aws_session_token"],
            }
        )
    elif config.profile:
        environment["AWS_PROFILE"] = config.profile
    return environment


def _parse_account(value: object) -> EcrAccount:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each AWS account entry must be a mapping")
    account_id = value.get("account_id")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise AwsDiscoveryError("account_id must be a quoted 12-digit AWS account ID")
    regions = _validated_strings(value.get("regions"), "regions", REGION_PATTERN)
    repositories = _validated_strings(value.get("repositories"), "repositories", REPOSITORY_PATTERN)
    role_arn = value.get("role_arn")
    if role_arn is not None:
        expected_prefix = f"arn:aws:iam::{account_id}:role/"
        if (
            not isinstance(role_arn, str)
            or not role_arn.startswith(expected_prefix)
            or not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", role_arn)
        ):
            raise AwsDiscoveryError(f"role_arn for account {account_id} is invalid")
    return EcrAccount(
        account_id=account_id,
        regions=regions,
        repositories=repositories,
        role_arn=role_arn,
    )


def _validated_strings(value: object, name: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise AwsDiscoveryError(f"{name} must be a non-empty list")
    if not all(isinstance(item, str) and pattern.fullmatch(item) for item in value):
        raise AwsDiscoveryError(f"{name} contains an invalid value")
    if len(set(value)) != len(value):
        raise AwsDiscoveryError(f"{name} must not contain duplicates")
    return tuple(value)


def discover_ecr_assets(
    config: EcrDiscoveryConfig,
    client_factory: ClientFactory | None = None,
) -> dict[str, object]:
    factory = client_factory or _boto3_client_factory(config.profile)
    assets: list[dict[str, object]] = []
    for account in config.accounts:
        credentials = _credentials_for_account(account, factory)
        for region in account.regions:
            client = factory("ecr", region, credentials)
            paginator = client.get_paginator("describe_images")
            for repository in account.repositories:
                try:
                    pages = paginator.paginate(
                        registryId=account.account_id,
                        repositoryName=repository,
                        filter={"tagStatus": "ANY"},
                    )
                    for page in pages:
                        for image in page.get("imageDetails", []):
                            asset = _image_asset(account.account_id, region, repository, image)
                            if asset is not None:
                                assets.append(asset)
                except Exception as exc:
                    raise AwsDiscoveryError(
                        f"ECR discovery failed for {account.account_id}/{region}/{repository}: {exc}"
                    ) from exc
    assets.sort(
        key=lambda item: (
            str(item["account_id"]),
            str(item["region"]),
            str(item["repository"]),
            str(item["digest"]),
        )
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "asset_count": len(assets),
        "assets": assets,
    }


def _credentials_for_account(account: EcrAccount, factory: ClientFactory) -> Mapping[str, str] | None:
    if account.role_arn:
        try:
            response = factory("sts", None, None).assume_role(
                RoleArn=account.role_arn,
                RoleSessionName="secscan-ecr-discovery",
            )
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
        raise AwsDiscoveryError(
            f"configured account {account.account_id} does not match caller account {caller_account}"
        )
    return None


def _image_asset(
    account_id: str,
    region: str,
    repository: str,
    image: Mapping[str, Any],
) -> dict[str, object] | None:
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


def _boto3_client_factory(profile: str | None) -> ClientFactory:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AwsDiscoveryError("AWS discovery requires the boto3 package") from exc
    session = boto3.Session(profile_name=profile)

    def factory(
        service: str,
        region: str | None,
        credentials: Mapping[str, str] | None,
    ) -> AwsClient:
        kwargs: dict[str, object] = {"region_name": region}
        if credentials:
            kwargs.update(credentials)
        return session.client(service, **kwargs)

    return factory


def write_ecr_assets(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
