# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source vulnerability-management platform that begins as a reliable Dockerized scanner and grows toward multi-target scanning, history, automation, and AWS-aware prioritization.

## Delivery principles

- Preserve local, no-cloud operation as the baseline.
- Keep scanner-specific behavior behind adapters and scanner plugins.
- Normalize all findings into a secscan-owned schema.
- Require automated packaging, test, and container validation before feature growth.
- Model current and projected operating costs before introducing paid infrastructure.

## Completed work

### Sprint 0 — Foundation and Planning

Established the repository, Agile workflow, initial architecture, roadmap, Definition of Done, Trivy strategy, and $0 infrastructure baseline.

### Sprint 1 — Dockerized Scanner MVP

Delivered public image scanning, normalized JSON, severity policy enforcement, deterministic exit codes, non-root execution, and a supported rootless-Docker workflow.

### Sprint 2 — SBOM and Human-Readable Reporting

Delivered raw Trivy JSON, normalized secscan JSON, CycloneDX JSON, and a standalone HTML report from one image scan.

### Sprint 3 — Engineering Foundation and Continuous Integration

Delivered pull-request CI for linting, mypy, pytest, wheel construction and inspection, clean installation, container startup, CodeQL, Dependabot, and fixable-critical container vulnerability enforcement.

## Current sprint

### Sprint 4A — Scanner Plugin Architecture

#### Goal

Introduce a stable scanner contract and registry so new target types can be added without coupling scanner implementations to the CLI, reporting, or policy layers.

#### User stories

1. As a maintainer, I can add a scanner by implementing one documented interface and registering it.
2. As a caller, I can submit a target-neutral `ScanRequest` and receive a normalized `ScanResult`.
3. As an existing user, `secscan scan image alpine:3.20` behaves exactly as before.

#### Planned implementation

- `Scanner` abstract base contract
- immutable `ScanRequest`, `ScanResult`, and scanner capability metadata
- explicit scanner registry with duplicate and unknown-scanner validation
- image scanner as the first registered plugin
- Trivy retained as an adapter beneath the image scanner
- CLI dispatch through the registry
- tests for registration, lookup, duplicate registration, unknown targets, and image scanner behavior
- package and wheel verification updated for scanner submodules
- architecture and Definition of Done updated with plugin boundaries

#### Architectural rules

- scanner plugins do not import or parse argparse
- scanner plugins do not write HTML or normalized JSON reports
- scanners return normalized findings rather than exposing engine-specific models
- scanner engines remain adapters and may be replaced without changing callers
- policy and report layers consume `ScanResult`, not engine output
- registration is explicit in Sprint 4A; dynamic third-party discovery is deferred

#### Acceptance criteria

- existing image-scan CLI syntax and artifacts remain compatible
- the registry contains the image scanner by default
- unknown scanner names produce an actionable operational error
- duplicate scanner names are rejected
- image scanning returns a normalized `ScanResult`
- all runtime scanner modules are present in the wheel and Docker image
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- filesystem, repository, SBOM, Kubernetes, or cloud scanners
- dynamic entry-point discovery
- remote plugins
- asynchronous execution
- running multiple scanners for one request

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. This sprint is a local code-architecture change and introduces no cloud services.

## Planned feature sprints

### Sprint 4B — Filesystem Scanning and Policy Configuration

Add a filesystem scanner plugin, read-only target mounts, reusable YAML policies, fix-availability gates, suppression reasons, and suppression expiration.

### Sprint 5 — Finding Comparison and Baselines

Compare current and previous results and classify findings as new, resolved, or unchanged using stable finding fingerprints.

### Sprint 6 — Local Scan History

Add a storage abstraction and SQLite implementation for target history, scan metadata, retention, trends, and remediation timing.

### Sprint 7 — Private Registry and ECR Support

Support temporary authentication, digest-first identity, credential redaction, retry behavior, and private ECR image scanning.

### Sprint 8 — Release Automation and Distribution

Publish immutable versioned images, checksums, provenance, release notes, upgrade guidance, and reusable consumer workflows.

### Sprint 9 — Service Mode and API

Add a long-running API, background jobs, bounded concurrency, health endpoints, and an optional PostgreSQL backend while preserving the standalone CLI.

### Sprint 10 — AWS Asset Discovery

Discover approved ECR assets across configured accounts and regions using documented least-privilege IAM permissions and an explicit cost model.

### Sprint 11 — Continuous Rescanning and Notifications

Track vulnerability database freshness, rescan unchanged assets when intelligence changes, calculate meaningful deltas, and suppress duplicate notifications.

### Sprint 12 — Exposure Context and Risk Prioritization

Add explainable AWS exposure evidence and contextual scoring without hiding raw severity or treating unavailable context as safe.

## Future epics

- additional scanner adapters such as Syft and Grype
- Git repository and SBOM target scanning
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- organization-wide delegated administration
- exploit-intelligence enrichment
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs.
