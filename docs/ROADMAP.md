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

### Sprint 4A — Scanner Plugin Architecture

Delivered scanner-neutral request and result contracts, an explicit registry, the image scanner as the first plugin, registry-driven CLI dispatch, and nested-module packaging controls.

## Current sprint

### Sprint 4B — Filesystem Scanning

#### Goal

Add a built-in filesystem scanner plugin that scans a local or mounted path while preserving the existing normalized findings, artifact names, policy behavior, and exit-code contract.

#### User stories

1. As a developer, I can scan the current project directory for vulnerable operating-system and language packages.
2. As an operator, I can mount an extracted root filesystem read-only and scan it without granting Docker-socket or privileged access.
3. As a CI user, I receive the same JSON, CycloneDX, HTML, summary, and policy exit behavior as an image scan.

#### Planned implementation

- `FilesystemScanner` plugin registered in the default scanner registry
- path expansion, resolution, existence validation, and readability validation
- Trivy filesystem adapter functions for vulnerability JSON and CycloneDX output
- unchanged report and policy pipeline
- read-only Docker mount examples
- tests for registration, missing paths, and normalized scanner output
- wheel, Docker, clean-install, and module-import verification for the new plugin

#### Acceptance criteria

- `secscan scan filesystem <path>` is available from the CLI
- missing targets fail with exit code `1` and an actionable message
- a valid target returns normalized `ScanResult` findings
- successful scans create `trivy.json`, `secscan.json`, `secscan.cdx.json`, and `secscan.html`
- policy violations continue to return exit code `2`
- documented Docker examples mount the target read-only
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- YAML policy files and suppression workflows
- Git repository, SBOM, Kubernetes, and cloud scanners
- host-agent installation
- automatic privilege escalation or protected-file bypass
- Docker-socket access

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Filesystem scans run locally or in existing GitHub Actions allowances and introduce no cloud services.

## Planned feature sprints

### Sprint 4C — Policy Configuration and Suppressions

Add reusable YAML policies, fix-availability gates, suppression reasons, suppression expiration, schema validation, and policy tests.

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
