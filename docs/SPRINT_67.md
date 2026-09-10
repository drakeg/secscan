# Sprint 67 — Bounded EKS/Kubernetes Workload Association

## Goal

Add a small, read-only EKS/Kubernetes workload association increment that connects explicitly approved Kubernetes workloads to immutable container-image targets without introducing cluster-wide discovery, workload mutation, agents, or paid AWS security services.

## Scope

This sprint will:

- require explicit AWS account, region, EKS cluster, namespace, and workload allow-lists
- validate cluster and Kubernetes identifiers before any API request
- verify same-account AWS caller identity or use one explicitly configured cross-account role
- resolve only explicitly approved EKS clusters
- obtain short-lived cluster authentication material without persisting it
- query only explicitly approved namespaces/workloads through least-privilege Kubernetes RBAC
- collect workload kind/name, namespace, container names, image references, and immutable `@sha256` image targets
- retain mutable tags as metadata only
- emit deterministic, schema-versioned JSON evidence
- fail closed when an approved cluster, namespace, workload, or required API response is missing or unexpected
- add a focused `secscan-eks` CLI entry point
- add tests, package integrity coverage, security/cost documentation, and roadmap advancement

## Initial supported workload boundary

The first increment should support only workload controllers that have stable pod-template container declarations and can be queried by exact name. Prefer a narrow set such as Deployments and StatefulSets rather than generic API-resource enumeration. Any additional workload kind discovered during implementation belongs in the backlog unless it is required to demonstrate the sprint goal.

## Security boundaries

- No cluster-wide enumeration or wildcard namespace/workload selection.
- No Kubernetes writes, exec, attach, port-forward, logs, secret reads, pod creation, rollout, scaling, deletion, or mutation.
- No node, daemon, or host access.
- No long-lived Kubernetes credential persistence.
- No implicit scan authorization; workload association only produces candidate immutable image targets.
- Mutable image tags are metadata and are never promoted to exact scan targets.
- Cross-account AWS access requires an explicitly configured role ARN.
- Kubernetes access must be documented with least-privilege RBAC limited to the exact read verbs/resources required by the supported workload kinds.
- Errors must not expose AWS credentials, bearer tokens, exec credential output, or other secret material.

## Cost

Current and projected recurring secscan service cost remains **$0**. The implementation uses read-only AWS/Kubernetes API calls with operator-provided credentials and introduces no hosted service, daemonset, agent, Inspector integration, or recurring infrastructure.

## Acceptance criteria

- configuration requires explicit account, region, cluster, namespace, workload kind, and workload name
- bounded limits prevent unbounded cluster/namespace/workload configuration
- same-account access verifies caller identity; cross-account access uses only the configured role
- only explicitly approved clusters and workloads are queried
- returned workloads outside the allow-list fail closed
- immutable image references are extracted deterministically; mutable tags remain metadata only
- output is deterministic except for the generation timestamp
- no secret-bearing authentication material appears in reports, logs, exceptions, or persisted files
- focused tests cover config validation, bounds, allow-list enforcement, missing/unexpected workloads, immutable-image extraction, and cross-account role behavior
- wheel/package integrity includes the new module and CLI entry point
- Python 3.12/3.14 quality/tests, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and separate GitHub Advanced Security CodeQL are green before merge

## Explicitly deferred

- EKS cluster enumeration
- wildcard namespaces or workloads
- Pods selected by label or arbitrary selectors
- Jobs/CronJobs/DaemonSets unless separately planned
- Helm inventory
- admission-controller integration
- Kubernetes vulnerability scanning beyond association to existing secscan image targets
- EKS API mutation or workload remediation
- node/host scanning
- in-cluster agents or daemonsets
- automatic scans triggered by discovery
- scheduling, retries, queues, or continuous reconciliation
