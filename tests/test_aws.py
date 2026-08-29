from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

import pytest

from secscan.aws import (
    AwsDiscoveryError,
    EcrAsset,
    discover_ec2_assets,
    discover_ecr_assets,
    ecr_scan_environment,
    load_ecr_asset,
    load_ecr_assets,
    load_ecr_config,
)


class FakePaginator:
    def __init__(self, images: list[dict[str, Any]]) -> None:
        self.images = images
        self.calls: list[dict[str, object]] = []

    def paginate(self, **kwargs: object) -> list[dict[str, object]]:
        self.calls.append(kwargs)
        return [{"imageDetails": self.images}]


class FakeEc2Paginator:
    def __init__(self, instances: list[dict[str, Any]]) -> None:
        self.instances = instances
        self.calls: list[dict[str, object]] = []

    def paginate(self, **kwargs: object) -> list[dict[str, object]]:
        self.calls.append(kwargs)
        return [{"Reservations": [{"Instances": self.instances}]}]


class FakeEcr:
    def __init__(self, paginator: FakePaginator) -> None:
        self.paginator = paginator

    def get_paginator(self, operation_name: str) -> FakePaginator:
        assert operation_name == "describe_images"
        return self.paginator


class FakeEc2:
    def __init__(self, paginator: FakeEc2Paginator) -> None:
        self.paginator = paginator

    def get_paginator(self, operation_name: str) -> FakeEc2Paginator:
        assert operation_name == "describe_instances"
        return self.paginator


class FakeSts:
    def __init__(self, account_id: str) -> None:
        self.account_id = account_id
        self.assume_role_calls: list[dict[str, str]] = []

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": self.account_id}

    def assume_role(self, **kwargs: str) -> dict[str, object]:
        self.assume_role_calls.append(kwargs)
        return {"Credentials": {"AccessKeyId": "access", "SecretAccessKey": "secret", "SessionToken": "token"}}


def _config(tmp_path: Path, content: str):
    path = tmp_path / "aws.yaml"
    path.write_text(content, encoding="utf-8")
    return load_ecr_config(path)


def test_load_ecr_config_requires_explicit_approved_targets(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
profile: secscan-readonly
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    repositories: [platform/api, platform/worker]
''')
    assert config.profile == "secscan-readonly"
    assert config.accounts[0].repositories == ("platform/api", "platform/worker")
    assert config.accounts[0].instances == ()


@pytest.mark.parametrize("content, message", [
    ("accounts: []", "at least one account"),
    ("accounts: [{account_id: 123, regions: [us-east-1], repositories: [app]}]", "quoted 12-digit"),
    ('accounts: [{account_id: "123456789012", regions: [bad], repositories: [app]}]', "regions contains an invalid value"),
    ('accounts: [{account_id: "123456789012", regions: [us-east-1], instances: [bad]}]', "instances contains an invalid value"),
    ('accounts: [{account_id: "123456789012", regions: [us-east-1]}]', "at least one repository or instance"),
])
def test_load_ecr_config_rejects_unbounded_or_invalid_config(tmp_path: Path, content: str, message: str) -> None:
    with pytest.raises(AwsDiscoveryError, match=message):
        _config(tmp_path, content)


def test_discover_ecr_assets_paginates_only_configured_repositories(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    repositories: [platform/api]
''')
    paginator = FakePaginator([{"imageDigest": "sha256:abc", "imageTags": ["latest", "1.2.3"], "imageSizeInBytes": 42, "imagePushedAt": datetime(2026, 8, 3, tzinfo=UTC)}])
    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else FakeEcr(paginator)
    report = discover_ecr_assets(config, factory)
    assert report["asset_count"] == 1
    assert report["assets"] == [{"account_id": "123456789012", "region": "us-east-1", "repository": "platform/api", "digest": "sha256:abc", "tags": ["1.2.3", "latest"], "size_bytes": 42, "pushed_at": "2026-08-03T00:00:00+00:00", "image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@sha256:abc"}]
    assert paginator.calls == [{"registryId": "123456789012", "repositoryName": "platform/api", "filter": {"tagStatus": "ANY"}}]


def test_discovery_rejects_implicit_cross_account_access(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    repositories: [app]
''')
    def factory(_service: str, _region: str | None, _credentials: object):
        return FakeSts("999999999999")
    with pytest.raises(AwsDiscoveryError, match="does not match caller account"):
        discover_ecr_assets(config, factory)


def test_load_ecr_asset_requires_exact_inventory_uri(tmp_path: Path) -> None:
    digest = f"sha256:{'a' * 64}"
    image_uri = f"123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@{digest}"
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"schema_version": 1, "assets": [{"account_id": "123456789012", "region": "us-east-1", "repository": "platform/api", "digest": digest, "image_uri": image_uri}]}), encoding="utf-8")
    asset = load_ecr_asset(inventory, image_uri)
    assert asset.digest == digest
    with pytest.raises(AwsDiscoveryError, match="not present"):
        load_ecr_asset(inventory, image_uri.replace(digest, f"sha256:{'b' * 64}"))


def test_ecr_scan_environment_uses_short_lived_role_credentials(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/SecscanEcrDiscovery
    regions: [us-east-1]
    repositories: [platform/api]
''')
    digest = f"sha256:{'a' * 64}"
    inventory = tmp_path / "inventory.json"
    image_uri = f"123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@{digest}"
    inventory.write_text(json.dumps({"schema_version": 1, "assets": [{"account_id": "123456789012", "region": "us-east-1", "repository": "platform/api", "digest": digest, "image_uri": image_uri}]}), encoding="utf-8")
    environment = ecr_scan_environment(config, load_ecr_asset(inventory, image_uri), lambda _service, _region, _credentials: FakeSts("123456789012"))
    assert environment == {"AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "access", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "token"}


def test_ecr_scan_environment_rechecks_repository_allow_list(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    repositories: [approved]
''')
    asset = EcrAsset("123456789012", "us-east-1", "not-approved", f"sha256:{'a' * 64}", f"123456789012.dkr.ecr.us-east-1.amazonaws.com/not-approved@sha256:{'a' * 64}")
    with pytest.raises(AwsDiscoveryError, match="repository is not approved"):
        ecr_scan_environment(config, asset)


def test_ecr_batch_selection_is_bounded_and_unique(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"schema_version": 1, "assets": []}), encoding="utf-8")
    image_uri = f"123456789012.dkr.ecr.us-east-1.amazonaws.com/app@sha256:{'a' * 64}"
    with pytest.raises(AwsDiscoveryError, match="must not contain duplicates"):
        load_ecr_assets(inventory, (image_uri, image_uri))
    with pytest.raises(AwsDiscoveryError, match="limit of 20"):
        load_ecr_assets(inventory, tuple(f"{image_uri}{index}" for index in range(21)))


def test_discover_ec2_assets_queries_only_allow_list_and_emits_literal_targets(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    instances: [i-0123456789abcdef0]
''')
    paginator = FakeEc2Paginator([{
        "InstanceId": "i-0123456789abcdef0",
        "State": {"Name": "running"},
        "PrivateIpAddress": "10.0.0.12",
        "PublicIpAddress": "198.51.100.7",
        "PrivateDnsName": "ip-10-0-0-12.ec2.internal",
        "PublicDnsName": "ec2-198-51-100-7.example.amazonaws.com",
        "VpcId": "vpc-123",
        "SubnetId": "subnet-123",
        "PlatformDetails": "Linux/UNIX",
        "LaunchTime": datetime(2026, 8, 1, tzinfo=UTC),
        "Tags": [{"Key": "Name", "Value": "api"}],
    }])
    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else FakeEc2(paginator)
    report = discover_ec2_assets(config, factory)
    assert report["asset_count"] == 1
    asset = report["assets"][0]
    assert asset["instance_id"] == "i-0123456789abcdef0"
    assert asset["candidate_targets"] == ["10.0.0.12", "198.51.100.7"]
    assert "ec2-198-51-100-7.example.amazonaws.com" not in asset["candidate_targets"]
    assert paginator.calls == [{"InstanceIds": ["i-0123456789abcdef0"]}]


def test_discover_ec2_assets_rejects_returned_instance_outside_allow_list(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    instances: [i-0123456789abcdef0]
''')
    paginator = FakeEc2Paginator([{"InstanceId": "i-fedcba98765432100"}])
    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else FakeEc2(paginator)
    with pytest.raises(AwsDiscoveryError, match="outside the configured allow-list"):
        discover_ec2_assets(config, factory)


def test_discover_ec2_assets_uses_explicit_cross_account_role(tmp_path: Path) -> None:
    config = _config(tmp_path, '''
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/SecscanEc2Discovery
    regions: [us-east-1]
    instances: [i-0123456789abcdef0]
''')
    sts = FakeSts("999999999999")
    paginator = FakeEc2Paginator([{"InstanceId": "i-0123456789abcdef0"}])
    def factory(service: str, _region: str | None, credentials: object):
        if service == "sts":
            return sts
        assert credentials == {"aws_access_key_id": "access", "aws_secret_access_key": "secret", "aws_session_token": "token"}
        return FakeEc2(paginator)
    report = discover_ec2_assets(config, factory)
    assert report["asset_count"] == 1
    assert sts.assume_role_calls == [{"RoleArn": "arn:aws:iam::123456789012:role/SecscanEc2Discovery", "RoleSessionName": "secscan-ec2-discovery"}]
