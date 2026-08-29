# Sprint 58 — Bounded ECS Workload Association

## Goal

Associate explicitly approved Amazon ECS services with the container images they deploy so operators can connect cloud workload identity to existing secscan image-assessment targets without enabling paid AWS scanning services, mutating workloads, or enumerating an account.

## Operator outcome

The new command:

```bash
secscan-ecs --config ecs.yaml --output /reports/ecs-workloads.json
```

reads a bounded allow-list and emits deterministic, schema-versioned workload association evidence.

Example configuration:

```yaml
profile: secscan-readonly
accounts:
  - account_id: "123456789012"
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api, worker]
```

Cross-account access remains explicit through an optional role ARN belonging to the configured account:

```yaml
accounts:
  - account_id: "123456789012"
    role_arn: arn:aws:iam::123456789012:role/SecscanEcsDiscovery
    regions: [us-east-1]
    ecs_services:
      - cluster: production
        services: [api]
```

## Scope

Sprint 58 adds:

- explicit ECS cluster/service allow-lists
- maximum 20 cluster scopes and 50 services per account
- same-account caller-identity verification
- explicit short-lived STS role assumption for cross-account discovery
- `DescribeServices` calls constrained to configured service names
- `DescribeTaskDefinition` lookups only for task definitions returned by approved services
- deterministic workload evidence containing account, region, cluster, service, status, desired/running counts, task definition, and sorted container metadata
- immutable image association only when a container image is already expressed as an exact `@sha256:<64 hex>` target
- a focused `secscan-ecs` CLI entry point and wheel packaging verification

## Security boundaries

The implementation intentionally does **not** call:

- `ListClusters`
- `ListServices`
- `ListTasks`
- `RunTask`
- `UpdateService`
- `RegisterTaskDefinition`
- ECS Exec
- AWS Inspector

An ECS response containing a service outside the configured allow-list is rejected. Missing approved services are also rejected rather than silently producing incomplete evidence.

Tag-based image references are retained as workload metadata but are not promoted to immutable secscan image targets. This avoids claiming a stable assessment association for a mutable tag.

No AWS credentials are persisted in secscan artifacts. Explicit role access uses short-lived STS credentials in memory.

## Out of scope

- automatic scans triggered from ECS discovery
- account-wide ECS enumeration
- task-level or container-instance enumeration
- EKS/Kubernetes workload association; this remains a follow-up backlog item so Kubernetes authentication/RBAC does not expand this sprint's security boundary
- changing ECS services, deployments, scaling, networking, or IAM
- billing or paid AWS security services

## Cost

Current and projected recurring secscan service/infrastructure cost remains **$0**. ECS and STS read API calls use existing operator AWS credentials; this sprint does not provision AWS resources or enable paid scanning services.

## Acceptance criteria

- invalid/unbounded ECS configuration is rejected
- same-account discovery verifies caller account identity
- cross-account discovery requires an explicit role ARN for the configured account
- service lookups contain only configured cluster/service values
- unexpected or missing services fail the discovery
- task definitions are followed only from approved returned services
- immutable digest image references are emitted as exact association targets
- mutable image tags remain metadata only
- output is deterministic and schema-versioned
- wheel verification includes the ECS core and CLI modules
- Ruff, mypy, pytest, wheel verification, clean install, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and separate GitHub Advanced Security CodeQL are green before merge

## Deferred follow-up

EKS workload association remains on the backlog. It should receive its own sprint because Kubernetes API authentication, cluster endpoint access, namespace/workload allow-lists, and RBAC introduce materially different security and operational boundaries from ECS read-only metadata.
