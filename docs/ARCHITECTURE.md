# secscan Architecture

## Purpose

This document is the living technical blueprint for secscan. It records current boundaries, data flow, module ownership, validation expectations, and the intended evolution from a standalone container scanner into a portable vulnerability-management platform.

## Architectural objectives

- Run as a self-contained, non-root Docker image.
- Support rootful and rootless Docker without requiring privileged mode.
- Avoid the Docker socket for the primary registry-image workflow.
- Keep target behavior in scanner plugins and engine behavior behind adapters.
- Own stable request, result, and finding models so callers are independent of engines.
- Produce deterministic artifacts for humans, CI systems, and future APIs.
- Preserve local, no-cloud operation as the baseline.
- Fail packaging and container validation before code is merged.

## Sprint 4A data flow

```text
CLI / future API / scheduled job
              |
              v
         ScanRequest
              |
              v
       ScannerRegistry
              |
              v
       ImageScanner plugin
              |
              v
         Trivy adapter
              |--------------------> raw Trivy JSON
              |--------------------> CycloneDX JSON SBOM
              v
          Normalizer
              |
              v
          ScanResult
              |--------------------> normalized secscan JSON
              |--------------------> standalone HTML report
              v
       Policy evaluator
              |
              +--------------------> summary and exit code
```

The CLI owns argument parsing and presentation. Scanner plugins own target orchestration. Engine adapters own subprocess details. Normalization, reporting, and policy remain project-level concerns.

## Repository layout

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
│   ├── trivy.py
│   └── scanners/
│       ├── __init__.py
│       ├── base.py
│       ├── registry.py
│       └── image.py
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

## Architectural rules

### Plugins never depend on the CLI

Scanner plugins accept `ScanRequest` values and return `ScanResult` values. They must not import argparse, inspect command-line arguments, print user-facing output, or translate exit codes.

### Plugins never generate reports

A scanner returns raw traceability data, normalized findings, and scanner metadata. The report layer decides how to emit normalized JSON, HTML, SARIF, SPDX, or future formats.

CycloneDX generation is treated as a scanner capability because it is produced by the underlying discovery engine, but the plugin receives an explicit destination from the caller and does not choose report names or layouts.

### Normalization is mandatory

Every scanner returns secscan-owned `Finding` objects. Policy and report code must not branch on Trivy, Grype, target type, or another engine-specific result shape.

### Tools are adapters

`ImageScanner` is a target plugin. Trivy is the initial engine adapter used by that plugin. A future engine may replace or complement Trivy without changing the registry, CLI request model, policy layer, or report layer.

### Registration is explicit

Sprint 4A uses an explicit default registry. Dynamic Python entry points, remote plugins, and untrusted plugin loading are deferred until their security and compatibility model is defined.

## Core contracts

### `ScanRequest`

An immutable request containing:

- scanner or target type
- target reference or path
- timeout
- optional output location needed for engine-native artifacts

The model is independent of argparse and can later be created by an API, scheduler, or test.

### `ScanResult`

An immutable result containing:

- the original request
- normalized findings
- raw engine payload for traceability
- scanner and engine metadata

Report and policy layers consume this result.

### `Scanner`

Every scanner provides:

- unique stable name
- human-readable description
- capability metadata
- `scan(request)`
- optional engine-native SBOM generation

### `ScannerRegistry`

The registry:

- registers scanner instances explicitly
- rejects duplicate names
- resolves a scanner by stable name
- lists registered capabilities deterministically
- raises an actionable error for unknown scanners

## Module responsibilities

### `cli.py`

- parse commands and options
- validate user input
- create `ScanRequest`
- resolve scanners through the registry
- invoke report and policy layers using `ScanResult`
- translate result categories into documented exit codes
- print concise status and actionable errors

The CLI must not implement engine-specific parsing or subprocess behavior.

### `scanners/base.py`

Own scanner-neutral contracts: `Scanner`, `ScannerCapability`, `ScanRequest`, and `ScanResult`.

### `scanners/registry.py`

Own registration, lookup, duplicate detection, and the default built-in scanner registry.

### `scanners/image.py`

Own container-image scan orchestration. It delegates package discovery, vulnerability matching, and CycloneDX generation to the Trivy adapter, then normalizes results before returning `ScanResult`.

### `trivy.py`

- invoke Trivy safely
- capture raw JSON
- generate CycloneDX output
- enforce subprocess timeouts
- distinguish scanner failures from vulnerability findings
- avoid exposing credentials in commands, logs, or artifacts

### `normalize.py`

- convert engine-specific output to `Finding` objects
- normalize unsupported or missing severity values
- preserve package, target, version, fix, and advisory information
- calculate severity summaries

### `models.py`

Own stable project-level finding data. Finding schema changes must be deliberate, backward-aware, and reflected in artifact versioning.

### `policy.py`

Evaluate normalized findings rather than raw engine output. Policy failure is distinct from scanner or internal failure.

### `report.py`

Write artifacts from normalized project-owned data. Reporting must not rerun the scanner or reinterpret engine results independently.

### `scripts/verify_wheel.py`

Validate that release and container wheels contain every required runtime module, including scanner subpackages. This is a build-integrity control.

## Artifact contract

A successful image scan currently produces:

- `trivy.json` — raw engine findings for traceability
- `secscan.json` — normalized project-owned findings
- `secscan.cdx.json` — CycloneDX SBOM
- `secscan.html` — self-contained human-readable report

Sprint 4A preserves these names and semantics.

## Exit-code contract

- `0` — scan completed and policy passed
- `1` — input, scanner, artifact, registry, or internal operational failure
- `2` — scan completed successfully but violated policy

A discovered vulnerability is not the same as a broken scan.

## Packaging and CI contract

Every pull request validates the complete delivery chain:

```text
source modules and scanner subpackages
    -> Ruff, mypy, and pytest
    -> wheel build
    -> wheel manifest verification
    -> clean wheel installation
    -> runtime module imports
    -> Docker image build
    -> CLI startup smoke test
    -> fixable-critical self-scan
    -> CodeQL
```

The Docker runtime stage installs a built wheel rather than executing beside an unpackaged source tree. Required scanner modules are tested after wheel installation and inside the image.

## Security boundaries

### Plugin loading

Only trusted, built-in plugins are registered in Sprint 4A. Dynamic discovery is deferred because arbitrary plugin loading is code execution and requires an explicit trust, versioning, and signing model.

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
- CI actions are version-pinned
- release images are scanned
- future release work adds signatures, provenance, and immutable digests

## Coding and design standards

- Python 3.12 is the current runtime baseline.
- Public functions and plugin contracts use type annotations.
- New target integrations implement `Scanner` rather than adding target conditionals to the CLI.
- New engines remain adapters beneath scanner plugins.
- New output formats consume project-owned normalized models.
- Tests accompany bug fixes and observable behavior changes.
- Security and cost implications are documented in every sprint and PR.
- Unrelated files are not changed as part of a focused sprint increment.

## Future service architecture

```text
API -> job queue -> scanner registry/workers -> normalized findings store
                              |                         |
                              v                         v
                         artifact store          comparison/risk engine
                                                         |
                                                         v
                                                  dashboard/alerts
```

Cloud components remain optional. Storage, queue, discovery, and notification integrations must retain local interfaces for development and small deployments.

## Architecture decision records

Material decisions should be captured under `docs/adr/`, including:

1. scanner-engine selection
2. scanner plugin trust and discovery model
3. normalized artifact schema and versioning
4. license
5. release registry
6. persistence technology
7. finding fingerprint strategy
8. API authentication
9. AWS discovery and contextual-risk boundaries
