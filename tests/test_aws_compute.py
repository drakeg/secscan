from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from secscan.assets import AssetRecord
from secscan.aws import AwsDiscoveryError
from secscan.aws_compute import associate_ec2_assets, discover_ec2_assets, load_ec2_config


class FakeSts:
    def __init__(self, account_id: str) -> None:
        self.account_id = account_id

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": self.account_id}

    def assume_role(self, **_kwargs: str) -> dict[str, object]:
        return {
            "Credentials": {
                "AccessKeyId": "access",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }


class FakeEc2:
    def __init__(self, instances: list[dict[str, Any]]) -> None:
        self.instances = instances
        self.calls: list[dict[str, object]] = []

    def describe_instances(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"Reservations": [{"Instances": self.instances}]}


def _config(tmp_path: Path, content: str):
    path = tmp_path / "ec2.yaml"
    path.write_text(content, encoding="utf-8")
    return load_ec2_config(path)


def test_load_ec2_config_requires_exact_instance_ids(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        """
profile: secscan-readonly
targets:
  - account_id: "123456789012"
    region: us-east-1
    instance_ids: [i-0123456789abcdef0]
""",
    )

    assert config.profile == "secscan-readonly"
    assert config.targets[0].instance_ids == ("i-0123456789abcdef0",)


@pytest.mark.parametrize(
    "content, message",
    [
        ("targets: []", "at least one target"),
        (
            'targets: [{account_id: "123456789012", region: us-east-1, instance_ids: [all]}]',
            "invalid EC2 instance ID",
        ),
        (
            'targets: [{account_id: "123456789012", region: bad, instance_ids: [i-0123456789abcdef0]}]',
            "region is invalid",
        ),
    ],
)
def test_load_ec2_config_rejects_unbounded_or_invalid_targets(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "ec2.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AwsDiscoveryError, match=message):
        load_ec2_config(path)


def test_discovery_calls_describe_instances_with_only_approved_ids(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        """
targets:
  - account_id: "123456789012"
    region: us-east-1
    instance_ids: [i-0123456789abcdef0]
""",
    )
    ec2 = FakeEc2(
        [
            {
                "InstanceId": "i-0123456789abcdef0",
                "State": {"Name": "running"},
                "InstanceType": "t3.small",
                "ImageId": "ami-0123456789abcdef0",
                "PlatformDetails": "Linux/UNIX",
                "PrivateIpAddress": "10.0.1.10",
                "PrivateDnsName": "ip-10-0-1-10.ec2.internal",
                "LaunchTime": datetime(2026, 8, 28, tzinfo=UTC),
            }
        ]
    )

    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else ec2

    report = discover_ec2_assets(config, factory)

    assert report["asset_count"] == 1
    assert ec2.calls == [{"InstanceIds": ["i-0123456789abcdef0"]}]
    asset = report["assets"][0]
    assert isinstance(asset, dict)
    assert asset["instance_id"] == "i-0123456789abcdef0"
    assert asset["private_ip"] == "10.0.1.10"
    assert asset["launch_time"] == "2026-08-28T00:00:00+00:00"


def test_discovery_fails_if_aws_omits_an_approved_instance(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        """
targets:
  - account_id: "123456789012"
    region: us-east-1
    instance_ids: [i-0123456789abcdef0]
""",
    )

    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else FakeEc2([])

    with pytest.raises(AwsDiscoveryError, match="did not return every approved instance"):
        discover_ec2_assets(config, factory)


def test_association_uses_only_exact_network_or_host_targets() -> None:
    report: dict[str, object] = {
        "schema_version": 1,
        "assets": [
            {
                "instance_id": "i-0123456789abcdef0",
                "private_ip": "10.0.1.10",
                "public_ip": None,
                "private_dns": "ip-10-0-1-10.ec2.internal",
                "public_dns": None,
            }
        ],
    }
    secscan_assets = [
        AssetRecord("a", "linux-host", "10.0.1.10", "first", "last", "job-1", 3),
        AssetRecord("b", "network", "ip-10-0-1-10.ec2.internal", "first", "last", "job-2", 1),
        AssetRecord("c", "web-dast", "https://10.0.1.10", "first", "last", "job-3", 2),
        AssetRecord("d", "network", "10.0.1.11", "first", "last", "job-4", 1),
    ]

    associated = associate_ec2_assets(report, secscan_assets)
    assets = associated["assets"]
    assert isinstance(assets, list)
    matches = assets[0]["secscan_associations"]
    assert [match["asset_id"] for match in matches] == ["a", "b"]
    assert associated["association_summary"] == {
        "ec2_assets_with_associations": 1,
        "ec2_assets_without_associations": 0,
        "matching": "exact-address-or-dns-target",
    }
