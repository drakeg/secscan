# Initial Architecture

## Architectural objectives

- Run as a self-contained Docker image.
- Avoid requiring privileged host access for the primary registry-image workflow.
- Keep scanner-engine details behind an adapter.
- Own a stable secscan finding model so engines can change later.
- Produce deterministic artifacts suitable for humans, CI systems, and future APIs.
- Preserve local, no-cloud operation as the baseline.

## MVP data flow

```text
CLI / container entrypoint
        |
        v
Input validation and target resolver
        |
        v
Scanner adapter (initially Trivy)
        |
        +----> raw engine JSON
        |
        v
Normalizer
        |
        v
secscan finding model
        |
        +----> normalized JSON
        |
        v
Policy evaluator
        |
        +----> summary and exit code
        |
        v
Report writers (added incrementally)
```

## Proposed repository layout

```text
secscan/
├── Dockerfile
├── pyproject.toml
├── README.md
├── docs/
│   ├── AGILE.md
│   ├── ARCHITECTURE.md
│   ├── DEFINITION_OF_DONE.md
│   └── ROADMAP.md
├── src/secscan/
│   ├── cli.py
│   ├── models.py
│   ├── policies.py
│   ├── errors.py
│   ├── adapters/
│   │   ├── base.py
│   │   └── trivy.py
│   └── reports/
│       ├── json_report.py
│       └── html_report.py
├── tests/
│   ├── fixtures/
│   ├── unit/
│   └── integration/
└── examples/
    └── policies/
```

This is a proposed structure and may be refined during Sprint 1. Changes should preserve the boundaries described below.

## Component responsibilities

### CLI and entrypoint

- parse commands and options
- validate user input
- create output directories
- invoke application services
- render concise status and errors
- translate result categories into documented process exit codes

The CLI must not contain scanner-specific parsing logic.

### Target resolver

- identify target type
- normalize image references
- preserve tag and resolved digest
- reject unsupported or ambiguous targets

### Scanner adapter

- invoke the external engine safely
- pin and report engine version
- capture raw output
- distinguish engine failures from discovered vulnerabilities
- avoid exposing credentials in commands, logs, or artifacts

### Normalizer

Convert engine-specific results into a secscan-owned model. Initial fields should include:

- schema version
- scan ID
- scan timestamp
- target type
- supplied target reference
- resolved digest when available
- scanner name and version
- vulnerability database metadata when available
- vulnerability ID
- package name and type
- installed version
- fixed version or versions
- severity
- title and description
- advisory/source references
- fix availability
- suppression state and reason

### Policy evaluator

- evaluate normalized findings, not raw engine data
- support deterministic severity thresholds
- return a policy result separately from scan success
- eventually support fix availability, package scope, suppressions, and expiration

### Report writers

Consume the normalized model. Report generation must not rerun or reinterpret the scanner engine.

## Exit-code contract

The exact numeric values will be finalized in Sprint 1, but categories must remain distinct:

- success with no policy violation
- successful scan with policy violation
- invalid user input or policy
- scanner/target failure
- internal secscan failure

This prevents CI from confusing a discovered critical vulnerability with a broken scan.

## Security boundaries

### Docker socket

The primary image-scanning workflow should pull from a registry and must not require mounting `/var/run/docker.sock`. Docker-socket access is effectively privileged and may be offered only as an explicitly documented optional workflow later.

### Filesystem scanning

Mounted targets should be read-only. secscan writes only to its designated output and cache locations.

### Credentials

- credentials are never copied into reports
- command output must redact secrets
- temporary AWS credentials are preferred for ECR
- scanner subprocesses should receive the minimum required environment

### Supply chain

- base images and scanner versions are pinned
- dependencies are locked
- release images are scanned
- later release sprints add signatures, provenance, and immutable digests

## Technology decisions

### Initial scanner: Trivy

Rationale:

- supports OCI images and filesystems
- produces vulnerability and SBOM output
- reduces the number of initial binaries
- has established CI and container workflows

Tradeoff:

- secscan initially depends on Trivy's detection behavior and database coverage
- the adapter and normalization layers are therefore mandatory, not optional abstraction

### Application language

Python is the initial recommendation for orchestration, normalization, policy, and report generation because it supports rapid development and readable data transformation. The external scanner remains responsible for package discovery and vulnerability matching.

This decision should be confirmed in Sprint 0 before implementation begins.

## Future architecture evolution

Later service mode may add:

```text
API -> job queue -> scanner workers -> normalized findings store
                          |                  |
                          v                  v
                     artifact store      risk engine
                                               |
                                               v
                                        dashboard/alerts
```

Cloud components must remain optional. Storage, queue, and notification integrations should use interfaces that retain a local implementation for development and small deployments.

## Architecture decision records

Material decisions should be captured under `docs/adr/`, beginning with:

1. initial scanner engine
2. implementation language
3. license
4. artifact schema/versioning
5. release registry
6. future persistence technology
