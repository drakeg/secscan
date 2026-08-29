from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from secscan.aws import AwsDiscoveryError
from secscan.aws_ecs import discover_ecs_workloads, load_ecs_config, write_ecs_workloads


class FakeSts:
    def __init__(self, account_id: str) -> None:
        self.account_id = account_id
        self.assume_role_calls: list[dict[str, str]] = []

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": self.account_id}

    def assume_role(self, **kwargs: str) -> dict[str, object]:
        self.assume_role_calls.append(kwargs)
        return {
            "Credentials": {
                "AccessKeyId": "access",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }


class FakeEcs:
    def __init__(
        self,
        services: list[dict[str, Any]],
        task_definitions: dict[str, dict[str, Any]],
        failures: list[dict[str, Any]] | None = None,
    ) -> None:
        self.services = services
        self.task_definitions = task_definitions
        self.failures = failures or []
        self.service_calls: list[dict[str, object]] = []
        self.task_definition_calls: list[dict[str, object]] = []

    def describe_services(self, **kwargs: object) -> dict[str, object]:
        self.service_calls.append(kwargs)
        return {"services": self.services, "failures": self.failures}

    def describe_task_definition(self, **kwargs: object) -> dict[str, object]:
        self.task_definition_calls.append(kwargs)
        task_definition = str(kwargs["taskDefinition"])
        return {"taskDefinition": self.task_definitions[task_definition]}


def _config(tmp_path: Path, content: str):
    path = tmp_path / "ecs.yaml"
    path.write_text(content, encoding="utf-8")
    return load_ecs_config(path)


def test_load_ecs_config_requires_explicit_bounded_services(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
profile: secscan-readonly
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api, worker]
''',
    )

    account = config.accounts[0]
    assert config.profile == "secscan-readonly"
    assert account.account_id == "123456789012"
    assert account.regions == ("us-east-1",)
    assert account.scopes[0].cluster == "production"
    assert account.scopes[0].services == ("api", "worker")


@pytest.mark.parametrize(
    "content, message",
    [
        ("accounts: []", "at least one account"),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1]}]',
            "ecs_services must be a non-empty list",
        ),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1], ecs_services: [{cluster: bad/name, services: [api]}]}]',
            "cluster contains an invalid value",
        ),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1], ecs_services: [{cluster: prod, services: [api, api]}]}]',
            "must not contain duplicates",
        ),
    ],
)
def test_load_ecs_config_rejects_unbounded_or_invalid_config(
    tmp_path: Path, content: str, message: str
) -> None:
    with pytest.raises(AwsDiscoveryError, match=message):
        _config(tmp_path, content)


def test_discover_ecs_workloads_describes_only_allow_list_and_links_immutable_images(
    tmp_path: Path,
) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api]
''',
    )
    task_definition = (
        "arn:aws:ecs:us-east-1:123456789012:task-definition/platform-api:42"
    )
    digest = "a" * 64
    immutable = (
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@sha256:" + digest
    )
    ecs = FakeEcs(
        services=[
            {
                "serviceName": "api",
                "status": "ACTIVE",
                "desiredCount": 2,
                "runningCount": 2,
                "taskDefinition": task_definition,
            }
        ],
        task_definitions={
            task_definition: {
                "containerDefinitions": [
                    {"name": "api", "image": immutable, "essential": True},
                    {"name": "sidecar", "image": "example/sidecar:latest", "essential": False},
                ]
            }
        },
    )

    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else ecs

    report = discover_ecs_workloads(config, factory)

    assert report["workload_count"] == 1
    workload = report["workloads"][0]
    assert workload["cluster"] == "production"
    assert workload["service"] == "api"
    assert workload["immutable_image_targets"] == [immutable]
    assert workload["containers"] == [
        {
            "name": "api",
            "image": immutable,
            "essential": True,
            "immutable_image_target": immutable,
        },
        {
            "name": "sidecar",
            "image": "example/sidecar:latest",
            "essential": False,
            "immutable_image_target": None,
        },
    ]
    assert ecs.service_calls == [{"cluster": "production", "services": ["api"]}]
    assert ecs.task_definition_calls == [{"taskDefinition": task_definition}]


def test_discover_ecs_workloads_rejects_service_outside_allow_list(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api]
''',
    )
    ecs = FakeEcs(
        services=[
            {
                "serviceName": "admin",
                "taskDefinition": "arn:aws:ecs:us-east-1:123456789012:task-definition/admin:1",
            }
        ],
        task_definitions={},
    )

    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else ecs

    with pytest.raises(AwsDiscoveryError, match="outside the configured allow-list"):
        discover_ecs_workloads(config, factory)


def test_discover_ecs_workloads_requires_all_approved_services(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api]
''',
    )
    ecs = FakeEcs(services=[], task_definitions={})

    def factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else ecs

    with pytest.raises(AwsDiscoveryError, match="approved ECS services were not returned: api"):
        discover_ecs_workloads(config, factory)


def test_discover_ecs_workloads_uses_explicit_cross_account_role(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/SecscanEcsDiscovery
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api]
''',
    )
    task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/api:1"
    sts = FakeSts("999999999999")
    ecs = FakeEcs(
        services=[{"serviceName": "api", "taskDefinition": task_definition}],
        task_definitions={task_definition: {"containerDefinitions": []}},
    )

    def factory(service: str, _region: str | None, credentials: object):
        if service == "sts":
            return sts
        assert credentials == {
            "aws_access_key_id": "access",
            "aws_secret_access_key": "secret",
            "aws_session_token": "token",
        }
        return ecs

    report = discover_ecs_workloads(config, factory)
    assert report["workload_count"] == 1
    assert sts.assume_role_calls == [
        {
            "RoleArn": "arn:aws:iam::123456789012:role/SecscanEcsDiscovery",
            "RoleSessionName": "secscan-ecs-discovery",
        }
    ]


def test_write_ecs_workloads_is_deterministic_json(tmp_path: Path) -> None:
    output = tmp_path / "ecs.json"
    report = {"schema_version": 1, "workload_count": 0, "workloads": []}

    write_ecs_workloads(report, output)

    assert json.loads(output.read_text(encoding="utf-8")) == report
    assert output.read_text(encoding="utf-8").endswith("\n")
