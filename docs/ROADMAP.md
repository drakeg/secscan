# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source vulnerability-management platform that begins as a reliable Dockerized scanner and grows toward multi-target scanning, history, automation, and AWS-aware prioritization.

## Delivery principles

- Preserve local, no-cloud operation as the baseline.
- Keep scanner-specific behavior behind adapters.
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

## Current sprint

### Sprint 3 — Engineering Foundation and Continuous Integration

#### Goal

Ensure every pull request proves that the Python package, wheel, Docker image, CLI, tests, and security checks work before merge.

#### Planned implementation

- GitHub Actions workflow for supported Python versions
- unit tests with pytest
- Ruff lint and format checks
- mypy static type checking
- Python wheel build and explicit wheel-content verification
- installed-package import smoke test
- Docker image build and `secscan --version` smoke test
- Trivy scan of the secscan image
- CodeQL workflow
- Dependabot configuration for Python, GitHub Actions, and Docker
- documented local developer commands

#### Acceptance criteria

- every pull request runs automated tests and static checks
- the built wheel contains every required runtime module
- a clean environment can install the wheel and import all CLI dependencies
- the Docker image builds and starts successfully
- CI stores useful failure output and fails at the earliest incorrect stage
- secscan scans its own image for known vulnerabilities
- no AWS resources are introduced

#### Cost outlook

Expected recurring infrastructure cost remains **$0** at low usage under included GitHub Actions allowances. Usage should be reviewed before enabling high-frequency, multi-architecture, or self-hosted builds.

## Planned feature sprints

### Sprint 4 — Filesystem Scanning and Policy Configuration

Add `scan filesystem`, read-only target mounts, reusable YAML policies, fix-availability gates, suppression reasons, and suppression expiration.

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
