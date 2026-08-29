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
ECS_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,255}$")
ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")
TASK_DEFINITION_ARN_PATTERN = re.compile(
    r"^arn:aws:ecs:[a-z]{2}-[a-z]+-[0-9]+:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:[0-9]+$"
)
MAX_ECS_SERVICE_SCOPES_PER_ACCOUNT = 20
MAX_ECS_SERVICES_PER_ACCOUNT = 50


class EcsClient(Protocol):
    def describe_services(self, **kwargs: object) -> Mapping[str, Any]: ...

    def describe_task_definition(self, **kwargs: object) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: str) -> Mapping[str, Any]: ...

    def get_caller_identity(self) -> Mapping[str, Any]: ...


ClientFactory = Callable[[str, str | None, Mapping[str, str] | None], object]


@dataclass(frozen=True)
class EcsServiceScope:
    cluster: str
    services: tuple[str, ...]


@dataclass(frozen=True)
class EcsAccount:
    account_id: str
    regions: tuple[str, ...]
    scopes: tuple[EcsServiceScope, ...]
    role_arn: str | None = None


@dataclass(frozen=True)
class EcsDiscoveryConfig:
    accounts: tuple[EcsAccount, ...]
    profile: str | None = None


def _validated_names(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise AwsDiscoveryError(f"{name} must be a non-empty list")
    if not all(isinstance(item, str) and ECS_NAME_PATTERN.fullmatch(item) for item in value):
        raise AwsDiscoveryError(f"{name} contains an invalid value")
    if len(set(value)) != len(value):
        raise AwsDiscoveryError(f"{name} must not contain duplicates")
    return tuple(value)


def _parse_account(value: object) -> EcsAccount:
    if not isinstance(value, dict):
        raise AwsDiscoveryError("each ECS account entry must be a mapping")
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

    raw_scopes = value.get("ecs_services")
    if not isinstance(raw_scopes, list) or not raw_scopes:
        raise AwsDiscoveryError("ecs_services must be a non-empty list")
    if len(raw_scopes) > MAX_ECS_SERVICE_SCOPES_PER_ACCOUNT:
        raise AwsDiscoveryError(
            f"ecs_services exceeds the limit of {MAX_ECS_SERVICE_SCOPES_PER_ACCOUNT} scopes per account"
        )
    scopes: list[EcsServiceScope] = []
    total_services = 0
    seen_clusters: set[str] = set()
    for raw_scope in raw_scopes:
        if not isinstance(raw_scope, dict):
            raise AwsDiscoveryError("each ecs_services entry must be a mapping")
        cluster = raw_scope.get("cluster")
        if not isinstance(cluster, str) or not ECS_NAME_PATTERN.fullmatch(cluster):
            raise AwsDiscoveryError("ecs_services cluster contains an invalid value")
        if cluster in seen_clusters:
            raise AwsDiscoveryError("ecs_services clusters must not contain duplicates")
        seen_clusters.add(cluster)
        services = _validated_names(raw_scope.get("services"), "ecs_services services")
        total_services += len(services)
        scopes.append(EcsServiceScope(cluster=cluster, services=services))
    if total_services > MAX_ECS_SERVICES_PER_ACCOUNT:
        raise AwsDiscoveryError(
            f"ecs_services exceeds the limit of {MAX_ECS_SERVICES_PER_ACCOUNT} services per account"
        )

    role_arn = value.get("role_arn")
    if role_arn is not None:
        expected_prefix = f"arn:aws:iam::{account_id}:role/"
        if (
            not isinstance(role_arn, str)
            or not role_arn.startswith(expected_prefix)
            or not ROLE_ARN_PATTERN.fullmatch(role_arn)
        ):
            raise AwsDiscoveryError(f"role_arn for account {account_id} is invalid")
    return EcsAccount(
        account_id=account_id,
        regions=tuple(raw_regions),
        scopes=tuple(scopes),
        role_arn=role_arn,
    )


def load_ecs_config(path: Path) -> EcsDiscoveryConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AwsDiscoveryError(f"could not read ECS discovery config: {exc}") from exc
    if not isinstance(data, dict):
        raise AwsDiscoveryError("ECS discovery config must be a mapping")
    raw_accounts = data.get("accounts")
    if not isinstance(raw_accounts, list) or not raw_accounts:
        raise AwsDiscoveryError("ECS discovery config must contain at least one account")
    profile = data.get("profile")
    if profile is not None and (not isinstance(profile, str) or not profile.strip()):
        raise AwsDiscoveryError("profile must be a non-empty string")
    accounts = tuple(_parse_account(value) for value in raw_accounts)
    if len({account.account_id for account in accounts}) != len(accounts):
        raise AwsDiscoveryError("account IDs must not contain duplicates")
    return EcsDiscoveryConfig(accounts=accounts, profile=profile)


def _boto3_client_factory(profile: str | None) -> ClientFactory:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise AwsDiscoveryError("ECS discovery requires the boto3 package") from exc
    session = boto3.Session(profile_name=profile)

    def factory(
        service: str, region: str | None, credentials: Mapping[str, str] | None
    ) -> object:
        kwargs: dict[str, object] = {"region_name": region}
        if credentials:
            kwargs.update(credentials)
        return session.client(service, **kwargs)

    return factory


def _credentials_for_account(
    account: EcsAccount, factory: ClientFactory
) -> Mapping[str, str] | None:
    if account.role_arn:
        try:
            sts = factory("sts", None, None)
            response = sts.assume_role(  # type: ignore[attr-defined]
                RoleArn=account.role_arn,
                RoleSessionName="secscan-ecs-discovery",
            )
            credentials = response["Credentials"]
            return {
                "aws_access_key_id": str(credentials["AccessKeyId"]),
                "aws_secret_access_key": str(credentials["SecretAccessKey"]),
                "aws_session_token": str(credentials["SessionToken"]),
            }
        except Exception as exc:
            raise AwsDiscoveryError(
                f"could not assume role for account {account.account_id}: {exc}"
            ) from exc
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


def _task_definition_images(
    client: EcsClient, task_definition_arn: str
) -> tuple[list[dict[str, object]], list[str]]:
    try:
        response = client.describe_task_definition(taskDefinition=task_definition_arn)
    except Exception as exc:
        raise AwsDiscoveryError(
            f"ECS task definition lookup failed for {task_definition_arn}: {exc}"
        ) from exc
    task_definition = response.get("taskDefinition")
    if not isinstance(task_definition, Mapping):
        raise AwsDiscoveryError("ECS returned an invalid task definition")
    containers: list[dict[str, object]] = []
    immutable_targets: set[str] = set()
    for definition in task_definition.get("containerDefinitions") or []:
        if not isinstance(definition, Mapping):
            continue
        name = str(definition.get("name") or "")
        image = str(definition.get("image") or "")
        if not name or not image:
            continue
        immutable = _immutable_image_target(image)
        if immutable:
            immutable_targets.add(immutable)
        containers.append(
            {
                "name": name,
                "image": image,
                "essential": bool(definition.get("essential", False)),
                "immutable_image_target": immutable,
            }
        )
    containers.sort(key=lambda item: (str(item["name"]), str(item["image"])))
    return containers, sorted(immutable_targets)


def discover_ecs_workloads(
    config: EcsDiscoveryConfig, client_factory: ClientFactory | None = None
) -> dict[str, object]:
    factory = client_factory or _boto3_client_factory(config.profile)
    workloads: list[dict[str, object]] = []
    for account in config.accounts:
        credentials = _credentials_for_account(account, factory)
        for region in account.regions:
            client = factory("ecs", region, credentials)
            for scope in account.scopes:
                try:
                    response = client.describe_services(  # type: ignore[attr-defined]
                        cluster=scope.cluster,
                        services=list(scope.services),
                    )
                except Exception as exc:
                    raise AwsDiscoveryError(
                        f"ECS service discovery failed for {account.account_id}/{region}/{scope.cluster}: {exc}"
                    ) from exc
                failures = response.get("failures") or []
                if failures:
                    raise AwsDiscoveryError(
                        f"ECS service discovery reported failures for {account.account_id}/{region}/{scope.cluster}"
                    )
                returned: set[str] = set()
                for service in response.get("services") or []:
                    if not isinstance(service, Mapping):
                        continue
                    service_name = str(service.get("serviceName") or "")
                    if service_name not in scope.services:
                        raise AwsDiscoveryError(
                            "ECS returned a service outside the configured allow-list"
                        )
                    returned.add(service_name)
                    task_definition_arn = str(service.get("taskDefinition") or "")
                    if not TASK_DEFINITION_ARN_PATTERN.fullmatch(task_definition_arn):
                        raise AwsDiscoveryError("ECS returned an invalid task definition ARN")
                    containers, immutable_targets = _task_definition_images(
                        client, task_definition_arn  # type: ignore[arg-type]
                    )
                    workloads.append(
                        {
                            "account_id": account.account_id,
                            "region": region,
                            "cluster": scope.cluster,
                            "service": service_name,
                            "status": str(service.get("status") or "unknown"),
                            "desired_count": int(service.get("desiredCount") or 0),
                            "running_count": int(service.get("runningCount") or 0),
                            "task_definition": task_definition_arn,
                            "containers": containers,
                            "immutable_image_targets": immutable_targets,
                        }
                    )
                missing = sorted(set(scope.services) - returned)
                if missing:
                    raise AwsDiscoveryError(
                        "approved ECS services were not returned: " + ", ".join(missing)
                    )
    workloads.sort(
        key=lambda item: (
            str(item["account_id"]),
            str(item["region"]),
            str(item["cluster"]),
            str(item["service"]),
        )
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "workload_count": len(workloads),
        "workloads": workloads,
    }


def write_ecs_workloads(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
