# secscan Architecture

## Purpose

This document is the living technical blueprint for secscan. It records current boundaries, data flow, module ownership, validation expectations, and the intended evolution from a standalone container scanner into a portable vulnerability-management platform.

## Architectural objectives

- Run as a self-contained, non-root Docker image.
- Support rootful and rootless Docker without requiring privileged mode.
- Avoid the Docker socket for the primary registry-image workflow.
- Keep scanner-engine details behind an adapter boundary.
- Own a stable normalized finding model so engines can change later.
- Produce deterministic artifacts for humans, CI systems, and future APIs.
- Preserve local, no-cloud operation as the baseline.
- Fail packaging and container validation before code is merged.

## Current data flow

```text
CLI / container entrypoint
        |
        v
Input validation
        |
        v
Trivy adapter
        |--------------------> raw Trivy JSON
        |--------------------> CycloneDX JSON SBOM
        v
Normalizer
        |
        v
secscan finding model
        |--------------------> normalized secscan JSON
        |--------------------> standalone HTML report
        v
Policy evaluator
        |
        +--------------------> summary and exit code
```

The scanner engine discovers packages and matches vulnerabilities. secscan owns orchestration, normalization, reporting, and policy behavior.

## Current repository layout

```text
secscan/
├── Dockerfile
├── pyproject.toml
├── README.md
├── secscan/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── normalize.py
│   ├── policy.py
│   ├── report.py
│   └── trivy.py
├── scripts/
│   └── verify_wheel.py
├── tests/
├── docs/
│   ├── AGILE.md
│   ├── ARCHITECTURE.md
│   ├── DEFINITION_OF_DONE.md
│   └── ROADMAP.md
└── .github/
    ├── workflows/
    └── dependabot.yml
```

The structure may become more deeply layered as adapters and report types grow, but module boundaries must remain explicit.

## Module responsibilities

### `cli.py`

- parse commands and options
- validate user input
- create output locations
- orchestrate adapters, normalization, reports, and policy evaluation
- translate result categories into documented exit codes
- print concise status and actionable errors

The CLI must not implement engine-specific parsing.

### `trivy.py`

- invoke Trivy safely
- capture raw JSON
- generate CycloneDX output
- enforce subprocess timeouts
- distinguish scanner failures from vulnerability findings
- avoid exposing credentials in commands, logs, or artifacts

Future engines must implement equivalent adapter behavior without changing the normalized schema contract.

### `normalize.py`

- convert engine-specific output to `Finding` objects
- normalize unsupported or missing severity values
- preserve package, target, version, fix, and advisory information
- calculate severity summaries

### `models.py`

Own the stable project-level data types. Schema changes must be deliberate, backward-aware, and reflected in artifact versioning.

### `policy.py`

Evaluate normalized findings rather than raw engine output. Policy failure is distinct from scanner or internal failure.

### `report.py`

Write artifacts from normalized data. Reporting must not rerun the scanner or reinterpret engine results independently.

### `scripts/verify_wheel.py`

Validate that release and container wheels contain every required runtime module. This is a build-integrity control, not an optional developer convenience.

## Artifact contract

A successful image scan currently produces:

- `trivy.json` — raw engine findings for traceability
- `secscan.json` — normalized project-owned findings
- `secscan.cdx.json` — CycloneDX SBOM
- `secscan.html` — self-contained human-readable report

Future changes should add artifacts rather than silently changing existing semantics. Breaking schema changes require a schema-version increment and migration guidance.

## Exit-code contract

- `0` — scan completed and policy passed
- `1` — input, scanner, artifact, or internal operational failure
- `2` — scan completed successfully but violated policy

A discovered vulnerability is not the same as a broken scan.

## Packaging and CI contract

Every pull request should validate the complete delivery chain:

```text
source modules
    -> Python tests and static checks
    -> wheel build
    -> wheel manifest verification
    -> clean wheel installation
    -> runtime module imports
    -> Docker image build
    -> CLI startup smoke test
    -> self-scan security check
```

The Docker runtime stage should install a built wheel rather than execute beside an unpackaged source tree. Required imports must be tested both after wheel installation and inside the image.

## Security boundaries

### Docker socket

Registry-image scanning must not require `/var/run/docker.sock`. Socket access may only be added later as an explicit high-privilege option.

### Rootless Docker

Docker-managed named volumes are the supported rootless path for report and cache persistence. The project must not require `0777`, `--privileged`, or disabling SELinux.

### Filesystem targets

Future mounted targets should be read-only. secscan writes only to designated output, cache, and history locations.

### Credentials

- credentials are never copied into reports
- logs and errors must redact secrets
- temporary credentials are preferred for private registries and AWS
- subprocesses receive the minimum required environment

### Supply chain

- base images and scanner versions are pinned
- Python packages are built and inspected as wheels
- CI actions should be version-pinned
- release images are scanned
- future release work adds signatures, provenance, and immutable digests

## Coding and design standards

- Python 3.12 is the current runtime baseline.
- Public functions should use type annotations.
- New scanner integrations use adapters rather than conditionals spread through the CLI.
- New output formats consume normalized models.
- Tests accompany bug fixes and observable behavior changes.
- Security and cost implications are documented in every sprint and PR.
- Unrelated files are not changed as part of a focused sprint increment.

## Future service architecture

```text
API -> job queue -> scanner workers -> normalized findings store
                           |                  |
                           v                  v
                      artifact store      comparison/risk engine
                                                |
                                                v
                                         dashboard/alerts
```

Cloud components remain optional. Storage, queue, discovery, and notification integrations must retain local interfaces for development and small deployments.

## Architecture decision records

Material decisions should be captured under `docs/adr/`, including:

1. scanner-engine selection
2. normalized artifact schema and versioning
3. license
4. release registry
5. persistence technology
6. finding fingerprint strategy
7. API authentication
8. AWS discovery and contextual-risk boundaries
