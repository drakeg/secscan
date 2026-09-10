from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, Protocol

import yaml

from secscan.aws import AwsDiscoveryError

ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]+$")
CLUSTER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
K8S_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")
SUPPORTED_KINDS = frozenset({"Deployment", "StatefulSet"})
MAX_EKS_CLUSTERS_PER_ACCOUNT = 10
MAX_EKS_WORKLOADS_PER_CLUSTER = 50


class EksClient(Protocol):
    def describe_cluster(self, **kwargs: object) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: str) -> Mapping[str, Any]: ...

    def get_caller_identity(self) -> Mapping[str, Any]: ...


class KubernetesReader(Protocol):
    def read_workload(self, namespace: str, kind: str, name: str) -> Mapping[str, Any]: ...


AwsClientFactory = Callable[[str, str | None, Mapping[str, str] | None], object]
KubernetesReaderFactory = Callable[[str, str, Mapping[str, str] | None], KubernetesReader]


@dataclass(frozen=True)
class EksWorkloadScope:
    namespace: str
    kind: str
    name: str


@dataclass(frozen=True)
class EksClusterScope:
    cluster: str
    workloads: tuple[EksWorkloadScope, ...]


@dataclass(frozen=True)
class EksAccount:
    account_id: str
    regions: tuple[str, ...]
    clusters: tuple[EksClusterScope, ...]
    role_arn: str | None = None


@dataclass(frozen=True)
class EksDiscoveryConfig:
    accounts: tuple[EksAccount, ...]
    profile: str | None = None


def _validated_k8s_name(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not K8S_NAME_PATTERN.fullmatch(value):
        raise AwsDiscoveryError(f"{field} contains an invalid Kubernetes name")
    return value


def _parse_workload(value: object) -> EksWorkloadScope:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each EKS workload entry must be a mapping")
    namespace = _validated_k8s_name(value.get("namespace"), "namespace")
    kind = value.get("kind")
    if kind not in SUPPORTED_KINDS:
        raise AwsDiscoveryError("kind must be Deployment or StatefulSet")
    name = _validated_k8s_name(value.get("name"), "workload name")
    return EksWorkloadScope(namespace=namespace, kind=str(kind), name=name)


def _parse_account(value: object) -> EksAccount:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each EKS account entry must be a mapping")
    account_id = value.get("account_id")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise AwsDiscoveryError("account_id must be a quoted 12-digit AWS account ID")
    raw_regions = value.get("regions")
    if not isinstance(raw_regions, list) or not raw_regions:
        raise AwsDiscoveryError("regions must be a non-empty list")
    if not all(isinstance(region, str) and REGION_PATTERN.fullmatch(region) for region in raw_regions):
        raise AwsDiscoveryError("regions contains an invalid value")
    if len(set(raw_regions)) != len(raw_regions):
        raise AwsDiscoveryError("regions must not contain duplicates")

    raw_clusters = value.get("eks_clusters")
    if not isinstance(raw_clusters, list) or not raw_clusters:
        raise AwsDiscoveryError("eks_clusters must be a non-empty list")
    if len(raw_clusters) > MAX_EKS_CLUSTERS_PER_ACCOUNT:
        raise AwsDiscoveryError(f"eks_clusters exceeds the limit of {MAX_EKS_CLUSTERS_PER_ACCOUNT} per account")
    clusters: list[EksClusterScope] = []
    seen_clusters: set[str] = set()
    for raw_cluster in raw_clusters:
        if not isinstance(raw_cluster, dict):
            raise AwsDiscoveryError("each eks_clusters entry must be a mapping")
        cluster = raw_cluster.get("cluster")
        if not isinstance(cluster, str) or not CLUSTER_NAME_PATTERN.fullmatch(cluster):
            raise AwsDiscoveryError("EKS cluster contains an invalid value")
        if cluster in seen_clusters:
            raise AwsDiscoveryError("EKS clusters must not contain duplicates")
        seen_clusters.add(cluster)
        raw_workloads = raw_cluster.get("workloads")
        if not isinstance(raw_workloads, list) or not raw_workloads:
            raise AwsDiscoveryError("EKS workloads must be a non-empty list")
        if len(raw_workloads) > MAX_EKS_WORKLOADS_PER_CLUSTER:
            raise AwsDiscoveryError(
                f"EKS workloads exceeds the limit of {MAX_EKS_WORKLOADS_PER_CLUSTER} per cluster"
            )
        workloads = tuple(_parse_workload(item) for item in raw_workloads)
        identities = {(item.namespace, item.kind, item.name) for item in workloads}
        if len(identities) != len(workloads):
            raise AwsDiscoveryError("EKS workloads must not contain duplicates")
        clusters.append(EksClusterScope(cluster=cluster, workloads=workloads))

    role_arn = value.get("role_arn")
    if role_arn is not None:
        expected_prefix = f"arn:aws:iam::{account_id}:role/"
        if (
            not isinstance(role_arn, str)
            or not role_arn.startswith(expected_prefix)
            or not ROLE_ARN_PATTERN.fullmatch(role_arn)
        ):
            raise AwsDiscoveryError(f"role_arn for account {account_id} is invalid")
    return EksAccount(
        account_id=account_id,
        regions=tuple(raw_regions),
        clusters=tuple(clusters),
        role_arn=role_arn,
    )


def load_eks_config(path: Path) -> EksDiscoveryConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AwsDiscoveryError(f"could not read EKS discovery config: {exc}") from exc
    if not isinstance(data, dict):
        raise AwsDiscoveryError("EKS discovery config must be a mapping")
    raw_accounts = data.get("accounts")
    if not isinstance(raw_accounts, list) or not raw_accounts:
        raise AwsDiscoveryError("EKS discovery config must contain at least one account")
    profile = data.get("profile")
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise AwsDiscoveryError("profile must be a non-empty string")
    accounts = tuple(_parse_account(item) for item in raw_accounts)
    if len({account.account_id for account in accounts}) != len(accounts):
        raise AwsDiscoveryError("account IDs must not contain duplicates")
    return EksDiscoveryConfig(accounts=accounts, profile=profile)


def _boto3_client_factory(profile: str | None) -> AwsClientFactory:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AwsDiscoveryError("EKS discovery requires the boto3 package") from exc
    session = boto3.Session(profile_name=profile)

    def factory(service: str, region: str | None, credentials: Mapping[str, str] | None) -> object:
        kwargs: dict[str, object] = {"region_name": region}
        if credentials:
            kwargs.update(credentials)
        return session.client(service, **kwargs)

    return factory


def _credentials_for_account(account: EksAccount, factory: AwsClientFactory) -> Mapping[str, str] | None:
    if account.role_arn:
        try:
            sts = factory("sts", None, None)
            response = sts.assume_role(  # type: ignore[attr-defined]
                RoleArn=account.role_arn,
                RoleSessionName="secscan-eks-discovery",
            )
            credentials = response["Credentials"]
            return {
                "aws_access_key_id": str(credentials["AccessKeyId"]),
                "aws_secret_access_key": str(credentials["SecretAccessKey"]),
                "aws_session_token": str(credentials["SessionToken"]),
            }
        except Exception as exc:
            raise AwsDiscoveryError(f"could not assume role for account {account.account_id}: {exc}") from exc
    try:
        sts = factory("sts", None, None)
        caller_account = str(sts.get_caller_identity()["Account"])  # type: ignore[attr-defined]
    except Exception as exc:
        raise AwsDiscoveryError(f"could not verify AWS caller identity: {exc}") from exc
    if caller_account != account.account_id:
        raise AwsDiscoveryError(
            f"configured account {account.account_id} does not match caller account {caller_account}"
        )
    return None


def _immutable_image_target(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    prefix, digest = value.rsplit("@sha256:", 1)
    if not prefix or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    return value


def _extract_containers(workload: Mapping[str, Any]) -> tuple[list[dict[str, object]], list[str]]:
    spec = workload.get("spec")
    if not isinstance(spec, Mapping):
        raise AwsDiscoveryError("Kubernetes returned a workload without spec")
    template = spec.get("template")
    if not isinstance(template, Mapping):
        raise AwsDiscoveryError("Kubernetes returned a workload without pod template")
    template_spec = template.get("spec")
    if not isinstance(template_spec, Mapping):
        raise AwsDiscoveryError("Kubernetes returned a workload without pod template spec")
    containers: list[dict[str, object]] = []
    immutable_targets: set[str] = set()
    for definition in template_spec.get("containers") or []:
        if not isinstance(definition, Mapping):
            continue
        name = str(definition.get("name") or "")
        image = str(definition.get("image") or "")
        if not name or not image:
            continue
        immutable = _immutable_image_target(image)
        if immutable:
            immutable_targets.add(immutable)
        containers.append({"name": name, "image": image, "immutable_image_target": immutable})
    containers.sort(key=lambda item: (str(item["name"]), str(item["image"])))
    return containers, sorted(immutable_targets)


def discover_eks_workloads(
    config: EksDiscoveryConfig,
    aws_client_factory: AwsClientFactory | None = None,
    kubernetes_reader_factory: KubernetesReaderFactory | None = None,
) -> dict[str, object]:
    if kubernetes_reader_factory is None:
        raise AwsDiscoveryError(
            "EKS workload association requires an explicit Kubernetes reader integration; no implicit cluster client is configured"
        )
    factory = aws_client_factory or _boto3_client_factory(config.profile)
    workloads: list[dict[str, object]] = []
    for account in config.accounts:
        credentials = _credentials_for_account(account, factory)
        for region in account.regions:
            eks = factory("eks", region, credentials)
            for cluster_scope in account.clusters:
                try:
                    response = eks.describe_cluster(name=cluster_scope.cluster)  # type: ignore[attr-defined]
                except Exception as exc:
                    raise AwsDiscoveryError(
                        f"EKS cluster lookup failed for {account.account_id}/{region}/{cluster_scope.cluster}: {exc}"
                    ) from exc
                cluster = response.get("cluster")
                if not isinstance(cluster, Mapping):
                    raise AwsDiscoveryError("EKS returned an invalid cluster response")
                returned_name = str(cluster.get("name") or "")
                if returned_name != cluster_scope.cluster:
                    raise AwsDiscoveryError("EKS returned a cluster outside the configured allow-list")
                status = str(cluster.get("status") or "unknown")
                reader = kubernetes_reader_factory(cluster_scope.cluster, region, credentials)
                for approved in cluster_scope.workloads:
                    try:
                        workload = reader.read_workload(approved.namespace, approved.kind, approved.name)
                    except Exception as exc:
                        raise AwsDiscoveryError(
                            f"Kubernetes workload lookup failed for {approved.namespace}/{approved.kind}/{approved.name}: {exc}"
                        ) from exc
                    metadata = workload.get("metadata")
                    if not isinstance(metadata, Mapping):
                        raise AwsDiscoveryError("Kubernetes returned a workload without metadata")
                    returned_namespace = str(metadata.get("namespace") or "")
                    returned_name = str(metadata.get("name") or "")
                    returned_kind = str(workload.get("kind") or "")
                    if (returned_namespace, returned_kind, returned_name) != (
                        approved.namespace,
                        approved.kind,
                        approved.name,
                    ):
                        raise AwsDiscoveryError("Kubernetes returned a workload outside the configured allow-list")
                    containers, immutable_targets = _extract_containers(workload)
                    workloads.append(
                        {
                            "account_id": account.account_id,
                            "region": region,
                            "cluster": cluster_scope.cluster,
                            "cluster_status": status,
                            "namespace": approved.namespace,
                            "kind": approved.kind,
                            "name": approved.name,
                            "containers": containers,
                            "immutable_image_targets": immutable_targets,
                        }
                    )
    workloads.sort(
        key=lambda item: (
            str(item["account_id"]),
            str(item["region"]),
            str(item["cluster"]),
            str(item["namespace"]),
            str(item["kind"]),
            str(item["name"]),
        )
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "workload_count": len(workloads),
        "workloads": workloads,
    }


def write_eks_workloads(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
