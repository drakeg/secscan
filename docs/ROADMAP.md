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

## Current sprint

### Sprint 4C — Policy Configuration and Suppressions

#### Goal

Add reusable YAML policies and temporary, auditable suppressions without hiding findings or changing the operational exit-code contract.

#### User stories

1. As a CI user, I can store the severity threshold in a version-controlled policy file.
2. As a security owner, I can temporarily suppress a specific vulnerability with a documented reason and expiration date.
3. As an auditor, I can see which findings were suppressed and why in the normalized report.
4. As an operator, I can override the policy threshold explicitly from the command line.

#### Planned implementation

- `--policy <path>` support for image and filesystem scans
- safe YAML loading and strict policy-shape validation
- policy-level `fail_on` threshold
- exact vulnerability suppressions with optional package matching
- mandatory suppression reason and ISO expiration date
- expired-suppression enforcement
- deterministic threshold precedence
- policy evaluation metadata in `secscan.json`
- unit tests for parsing, matching, expiration, and validation
- README, architecture, and policy-guide updates

#### Precedence

1. explicit CLI `--fail-on`
2. YAML `policy.fail_on`
3. built-in `CRITICAL` default

Suppressions are evaluated before severity-policy failure. Expired suppressions never affect results.

#### Acceptance criteria

- valid YAML policies load for both scanner types
- invalid YAML or schema errors produce exit code `1`
- suppressions require vulnerability, reason, and expiration
- package-scoped suppressions match only the named package
- suppressed findings remain visible in report policy metadata
- only active findings determine exit code `2`
- CLI `--fail-on` overrides the file threshold
- CI and CodeQL pass before merge
- no AWS resources or paid infrastructure are introduced

#### Out of scope

- fix-availability, age, exploitability, and package-deny rules
- wildcard or regular-expression matching
- remote or signed policy bundles
- suppression approval workflows
- centralized policy distribution

#### Cost outlook

Current and projected recurring infrastructure cost remains **$0**. Policy evaluation is local and introduces only a small Python YAML dependency.

## Planned feature sprints

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
