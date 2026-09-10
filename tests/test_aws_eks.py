from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secscan.aws import AwsDiscoveryError
from secscan.aws_eks import discover_eks_workloads, load_eks_config


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


class FakeEks:
    def __init__(self, cluster: dict[str, Any]) -> None:
        self.cluster = cluster
        self.calls: list[dict[str, object]] = []

    def describe_cluster(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"cluster": self.cluster}


class FakeReader:
    def __init__(self, workloads: dict[tuple[str, str, str], dict[str, Any]]) -> None:
        self.workloads = workloads
        self.calls: list[tuple[str, str, str]] = []

    def read_workload(self, namespace: str, kind: str, name: str) -> dict[str, Any]:
        key = (namespace, kind, name)
        self.calls.append(key)
        return self.workloads[key]


def _config(tmp_path: Path, content: str):
    path = tmp_path / "eks.yaml"
    path.write_text(content, encoding="utf-8")
    return load_eks_config(path)


def test_load_eks_config_requires_explicit_workloads(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    eks_clusters:
      - cluster: production
        workloads:
          - namespace: app
            kind: Deployment
            name: api
''',
    )
    workload = config.accounts[0].clusters[0].workloads[0]
    assert workload.namespace == "app"
    assert workload.kind == "Deployment"
    assert workload.name == "api"


@pytest.mark.parametrize(
    "content, message",
    [
        ("accounts: []", "at least one account"),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1]}]',
            "eks_clusters must be a non-empty list",
        ),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1], eks_clusters: [{cluster: prod, workloads: [{namespace: App, kind: Deployment, name: api}]}]}]',
            "invalid Kubernetes name",
        ),
        (
            'accounts: [{account_id: "123456789012", regions: [us-east-1], eks_clusters: [{cluster: prod, workloads: [{namespace: app, kind: Pod, name: api}]}]}]',
            "kind must be Deployment or StatefulSet",
        ),
    ],
)
def test_load_eks_config_rejects_unbounded_or_invalid_config(
    tmp_path: Path, content: str, message: str
) -> None:
    with pytest.raises(AwsDiscoveryError, match=message):
        _config(tmp_path, content)


def test_discover_eks_workloads_queries_only_approved_workload_and_extracts_digest(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    eks_clusters:
      - cluster: production
        workloads:
          - namespace: app
            kind: Deployment
            name: api
''',
    )
    digest_image = "example.com/api@sha256:" + "a" * 64
    eks = FakeEks({"name": "production", "status": "ACTIVE"})
    reader = FakeReader(
        {
            ("app", "Deployment", "api"): {
                "kind": "Deployment",
                "metadata": {"namespace": "app", "name": "api"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "api", "image": digest_image},
                                {"name": "sidecar", "image": "example.com/sidecar:latest"},
                            ]
                        }
                    }
                },
            }
        }
    )

    def aws_factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else eks

    def reader_factory(_cluster: str, _region: str, _credentials: object):
        return reader

    report = discover_eks_workloads(config, aws_factory, reader_factory)
    workload = report["workloads"][0]
    assert workload["immutable_image_targets"] == [digest_image]
    assert reader.calls == [("app", "Deployment", "api")]
    assert eks.calls == [{"name": "production"}]


def test_discover_eks_workloads_rejects_unexpected_returned_workload(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    eks_clusters:
      - cluster: production
        workloads:
          - namespace: app
            kind: Deployment
            name: api
''',
    )
    eks = FakeEks({"name": "production", "status": "ACTIVE"})
    reader = FakeReader(
        {
            ("app", "Deployment", "api"): {
                "kind": "Deployment",
                "metadata": {"namespace": "app", "name": "admin"},
                "spec": {"template": {"spec": {"containers": []}}},
            }
        }
    )

    def aws_factory(service: str, _region: str | None, _credentials: object):
        return FakeSts("123456789012") if service == "sts" else eks

    with pytest.raises(AwsDiscoveryError, match="outside the configured allow-list"):
        discover_eks_workloads(config, aws_factory, lambda *_args: reader)


def test_discover_eks_workloads_uses_explicit_cross_account_role(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        '''
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/SecscanEksDiscovery
    regions: [us-east-1]
    eks_clusters:
      - cluster: production
        workloads:
          - namespace: app
            kind: StatefulSet
            name: db
''',
    )
    sts = FakeSts("999999999999")
    eks = FakeEks({"name": "production", "status": "ACTIVE"})
    reader = FakeReader(
        {
            ("app", "StatefulSet", "db"): {
                "kind": "StatefulSet",
                "metadata": {"namespace": "app", "name": "db"},
                "spec": {"template": {"spec": {"containers": []}}},
            }
        }
    )

    def aws_factory(service: str, _region: str | None, credentials: object):
        if service == "sts":
            return sts
        assert credentials == {
            "aws_access_key_id": "access",
            "aws_secret_access_key": "secret",
            "aws_session_token": "token",
        }
        return eks

    discover_eks_workloads(config, aws_factory, lambda *_args: reader)
    assert sts.assume_role_calls == [
        {
            "RoleArn": "arn:aws:iam::123456789012:role/SecscanEksDiscovery",
            "RoleSessionName": "secscan-eks-discovery",
        }
    ]
