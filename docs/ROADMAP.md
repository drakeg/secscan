# Product Roadmap and Sprint Plans

## Product goal

Deliver a portable, open-source vulnerability-management platform that begins as a reliable Dockerized scanner and grows toward multi-target scanning, history, automation, and AWS-aware prioritization.

## Delivery principles

- Preserve local, no-cloud operation as the baseline.
- Keep scanner-specific behavior behind adapters and scanner plugins.
- Normalize all findings into a secscan-owned schema.
- Require automated packaging, test, and container validation before feature growth.
- Model current and projected operating costs before introducing paid infrastructure.
- Capture new ideas in the backlog instead of expanding an active sprint.

## Completed work

### Sprint 0 — Foundation and Planning

Established the repository, Agile workflow, architecture, roadmap, Definition of Done, Trivy strategy, and $0 infrastructure baseline.

### Sprint 1 — Dockerized Scanner MVP

Delivered public image scanning, normalized JSON, severity policy enforcement, deterministic exit codes, non-root execution, and a supported rootless-Docker workflow.

### Sprint 2 — SBOM and Human-Readable Reporting

Delivered raw Trivy JSON, normalized secscan JSON, CycloneDX JSON, and a standalone HTML report.

### Sprint 3 — Engineering Foundation and Continuous Integration

Delivered CI for Ruff, mypy, pytest, wheel integrity, clean installation, container startup, CodeQL, Dependabot, and fixable-critical container vulnerability enforcement.

### Sprint 4A — Scanner Plugin Architecture

Delivered scanner-neutral contracts, an explicit registry, the image scanner plugin, registry-driven CLI dispatch, and nested-module packaging controls.

### Sprint 4B — Filesystem Scanning

Delivered the filesystem scanner plugin, read-only mount guidance, Trivy filesystem and CycloneDX adapters, path validation, and target-aware reports.

### Sprint 4C — Policy Configuration and Suppressions

Delivered safe YAML policies, threshold precedence, expiring auditable suppressions, policy metadata, and strict validation.

### Sprint 5 — Finding Comparison and Baselines

Delivered stable finding fingerprints, `--baseline`, new/resolved/unchanged classification, `secscan.diff.json`, strict baseline validation, and same-output-path baseline safety.

### Sprint 5.5 — Local Scan History

Delivered a versioned SQLite history store, automatic scan metadata recording, `secscan history`, `secscan show`, migration tests, and local-only operation.

### Sprint 6 — Repository Scanning

Delivered a repository scanner plugin for checked-out source trees using the existing normalization, policy, baseline, reporting, history, and exit-code pipelines.

### Sprint 7 — SBOM Ingestion

Delivered CycloneDX JSON validation, Trivy SBOM vulnerability scanning, normalized findings, standard artifact preservation, and scanner-neutral policy, baseline, history, and reporting integration.

### Sprint 8 — Policy v2

Delivered typed, explainable rules for packages, vulnerability IDs, severities, fix availability, and vulnerability age while preserving existing policy compatibility.

## Current sprint

### Sprint 14 — Local Historical Trends

#### Goal

Turn existing local scan-level history into bounded, machine-readable trend summaries without introducing a service, cloud database, or finding-level retention.

#### User stories

1. As an operator, I can inspect severity totals across recent scans of one target and scanner.
2. As an automation author, I can save a versioned JSON trend document.
3. As a security owner, I can see the net severity change from the oldest included scan to the newest.
4. As an existing user, my history database continues to work without migration or duplication.

#### Planned implementation

- a `secscan trends` command requiring an exact scanner and target cohort
- a bounded 2–100 scan window, ordered oldest to newest
- latest severity totals and signed change since the oldest included scan
- versioned JSON output with atomic replacement
- readable console output when no output file is selected
- query, validation, serialization, CLI, and compatibility tests
- history, roadmap, architecture, README, and local test-procedure updates

#### Acceptance criteria

- trends contain only records matching both the exact scanner and target
- the most recent bounded records are returned in chronological order
- fewer than two matching scans fail clearly instead of implying a trend
- JSON records its schema version, cohort, time range, latest totals, signed changes, and series
- existing version 1 history databases remain compatible without schema migration
- trend generation does not mutate scan records or read detailed report artifacts
- branch preflight, CI, and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- charts, dashboards, forecasting, or cross-target aggregation
- finding-level persistence or vulnerability lifecycle correlation
- mean time to remediation, because scan-level totals cannot establish finding identity
- remote history stores, scheduled analysis, or service API endpoints

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Trend computation reads the existing local SQLite database and introduces no external services.

## Planned feature sprints

### Sprint 9 — Service Mode and API

Delivered a long-running local API, background jobs, bounded concurrency, health and job status endpoints, and allow-listed artifact downloads while preserving the standalone CLI.

### Sprint 10 — Persistent Service Job Management

Delivered SQLite-backed service job metadata, restart recovery, filtered recent-job listing, and safe queued-job cancellation.

#### Stories and acceptance criteria

- submitted jobs are recorded before worker execution and remain queryable after restart
- jobs interrupted by a restart are marked failed rather than replayed automatically
- `GET /api/v1/jobs` returns newest-first results with optional `status`, `scanner`, and bounded `limit` filters
- `DELETE /api/v1/jobs/{job_id}` cancels only queued jobs and rejects running or terminal jobs
- the existing submit, status, artifact, CLI, and scanner behavior remains compatible
- SQLite and the local filesystem remain the only service-state dependencies
- restart recovery, filtering, cancellation races, and endpoint responses have automated tests
- documentation, branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- active scanner processes are never terminated through the API
- cancelled jobs are retained for auditability; this sprint adds no deletion endpoint
- interrupted work is not automatically replayed against potentially changed targets
- current and projected recurring infrastructure cost remains **$0**

### Sprint 11 — AWS Asset Discovery

Delivered read-only discovery of exact ECR repositories across approved accounts and regions with versioned inventory output and documented least-privilege IAM.

#### Stories and acceptance criteria

- YAML configuration requires explicit account IDs, regions, and exact repository names
- same-account discovery verifies the caller account before accessing ECR
- cross-account discovery uses one explicitly configured role ARN and short-lived credentials
- paginated `DescribeImages` results produce a versioned JSON inventory with immutable digest URIs
- discovery does not enumerate repositories, pull images, start scans, or mutate AWS resources
- credential-free tests cover configuration validation, repository scoping, pagination, output, and account rejection
- local automated and optional live AWS testing procedures are documented
- least-privilege IAM, security boundaries, and the projected cost remain documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- credentials and session tokens are never persisted
- exact repository allow-lists prevent unbounded discovery
- output is treated as security-sensitive infrastructure inventory
- current and projected recurring secscan infrastructure cost remains **$0**

### Sprint 12 — Authenticated ECR Scanning

Delivered authenticated scanning of one explicitly selected immutable ECR image through the existing image, policy, baseline, reporting, SBOM, history, and exit-code pipeline.

#### Stories and acceptance criteria

- `secscan scan ecr` requires an exact digest URI present in a schema-versioned inventory
- the inventory account, region, and repository are rechecked against the AWS allow-list
- same-account scans use the standard AWS credential chain or configured profile
- cross-account scans use short-lived assumed-role credentials
- AWS credentials are passed only through the Trivy child-process environment and are never written to commands, reports, history, or logs
- existing policy, baseline, JSON, HTML, CycloneDX, history, timeout, and exit-code behavior remains available
- credential-free tests cover inventory selection, allow-list rejection, credential handling, CLI parsing, and child-process isolation
- local automated and optional live ECR testing procedures remain documented
- least-privilege pull permissions, security boundaries, and potential data-transfer costs are documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- only one exact inventory digest is scanned per command
- batch selection, scheduling, repository enumeration, and service-mode ECR scans remain out of scope
- credentials and authorization tokens are never persisted
- current recurring secscan infrastructure cost remains **$0**; users retain responsibility for AWS data-transfer and registry costs

### Sprint 13 — Bounded ECR Batch Scanning

Delivered sequential batches of up to 20 explicitly selected immutable ECR inventory URIs with isolated artifacts, shared history, and a machine-readable batch manifest.

#### Stories and acceptance criteria

- users repeat `--image-uri` to select exact digest URIs from the versioned inventory
- selections must be unique, present in the inventory, approved by configuration, and limited to 20
- the complete inventory and allow-list selection is validated before the first scan starts
- scans run sequentially and reuse authenticated ECR scanning without adding a scheduler or queue
- each image writes to a deterministic index-and-digest directory beneath an initially empty output root
- batch history uses one shared SQLite database unless history is disabled or another path is supplied
- `batch.json` records each selected URI, output directory, status, exit code, and the aggregate exit code
- aggregate exit code is `1` for any operational failure, otherwise `2` for any policy failure, otherwise `0`
- credential-free tests cover bounds, duplicates, CLI selection, output isolation, manifests, and exit aggregation
- local automated and optional live batch testing procedures remain documented
- branch preflight, CI, and CodeQL pass before merge

#### Security and cost boundaries

- no tag, wildcard, repository-wide, or implicit “all images” selection is supported
- concurrency, scheduling, retries, resume, and service-mode batch submission remain out of scope
- the output root must be empty to prevent accidental artifact overwrite
- current recurring secscan infrastructure cost remains **$0**; users retain responsibility for per-image AWS data-transfer and registry costs

## Future epics and backlog

- SPDX and additional SBOM formats
- SBOM package and license intelligence
- cross-source correlation
- additional private registry authentication
- release automation, immutable images, provenance, and checksums
- finding-level history and mean time to remediation
- additional scanner adapters such as Syft and Grype
- risk scoring, KEV, and EPSS enrichment
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs. Ideas discovered during a sprint are added to the backlog rather than changing the active sprint scope.
