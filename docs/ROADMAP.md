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

### Sprint 4B — Filesystem Scanning

Delivered the filesystem scanner plugin, read-only mount guidance, Trivy filesystem and CycloneDX adapters, path validation, target-aware reports, and packaging coverage.

### Sprint 4C — Policy Configuration and Suppressions

Delivered safe YAML policies, threshold precedence, expiring auditable suppressions, policy metadata, and strict validation.

## Current sprint

### Sprint 5 — Finding Comparison and Baselines

#### Goal

Compare current findings with a prior normalized report and classify findings as new, resolved, or unchanged using stable secscan-owned fingerprints.

#### User stories

1. As a CI user, I can identify vulnerabilities introduced since the last successful scan.
2. As a security owner, I can see which previously observed findings are resolved.
3. As an auditor, I can reproduce the comparison from two normalized secscan reports.
4. As an operator, I can use comparison without changing existing policy and exit-code behavior.

#### Planned implementation

- `--baseline <secscan.json>` for image and filesystem scans
- stable SHA-256 finding fingerprints
- fingerprint identity based on vulnerability, package, target, and package type
- `secscan.diff.json` with `new`, `resolved`, and `unchanged` collections
- strict baseline JSON and schema validation
- tests for fingerprints, classification, and invalid baselines
- package, wheel, clean-install, and container checks for the comparison module
- CI validation on Python 3.12 and Python 3.14
- README, architecture, and baseline-guide updates

#### Acceptance criteria

- current-only findings are classified as `new`
- baseline-only findings are classified as `resolved`
- findings present in both reports are classified as `unchanged`
- changes to severity, title, installed version, fixed version, or URL do not create false new findings
- missing or malformed baselines fail with exit code `1`
- comparison does not alter policy evaluation or exit code `2`
- wheel and container validation include the comparison module
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- automatic baseline storage or selection
- historical trend databases
- policy rules that fail only on new findings
- comparison across unrelated targets
- semantic package renaming or vulnerability alias resolution

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Comparison is local and uses existing report files.

## Planned feature sprints

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

- richer policy rules for fix availability, age, package, and exploit intelligence
- additional scanner adapters such as Syft and Grype
- Git repository and SBOM target scanning
- EC2 inventory or snapshot-based scanning
- ECS and EKS workload association
- web dashboard and multi-user access
- organization-wide delegated administration
- Jira, Slack, ServiceNow, SIEM, and GitHub integrations
- signed policy bundles and enterprise governance

## Backlog rules

The roadmap is directional. A future sprint becomes committed only after planning confirms its stories, acceptance criteria, dependencies, security implications, validation strategy, and projected operating costs.
