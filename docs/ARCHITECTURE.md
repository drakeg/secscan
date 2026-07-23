# secscan Architecture

## Purpose

This document is the living technical blueprint for secscan. It records current boundaries, data flow, module ownership, validation expectations, and the intended evolution from a standalone scanner into a portable vulnerability-management platform.

## Architectural objectives

- Run as a self-contained, non-root Docker image.
- Support rootful and rootless Docker without requiring privileged mode.
- Avoid the Docker socket for normal image and filesystem workflows.
- Keep target behavior in scanner plugins and engine behavior behind adapters.
- Own stable request, result, and finding models so callers are independent of engines.
- Produce deterministic artifacts for humans, CI systems, and future APIs.
- Preserve local, no-cloud operation as the baseline.
- Fail packaging and container validation before code is merged.

## Current data flow

```text
CLI / future API / scheduled job
              |
              v
         ScanRequest
              |
              v
       ScannerRegistry
          /       \
         v         v
 ImageScanner   FilesystemScanner
         \         /
          v       v
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

The CLI owns argument parsing and presentation. Scanner plugins own target validation and orchestration. Engine adapters own subprocess details. Normalization, reporting, and policy remain project-level concerns.

## Repository layout

```text
secscan/
├── Dockerfile
├── pyproject.toml
├── README.md
├── secscan/
│   ├── cli.py
│   ├── models.py
│   ├── normalize.py
│   ├── policy.py
│   ├── report.py
│   ├── trivy.py
│   └── scanners/
│       ├── base.py
│       ├── registry.py
│       ├── image.py
│       └── filesystem.py
├── scripts/
│   └── verify_wheel.py
├── tests/
├── docs/
└── .github/
```

## Architectural rules

### Plugins never depend on the CLI

Scanner plugins accept `ScanRequest` values and return `ScanResult` values. They do not import argparse, print user-facing output, choose exit codes, or know whether the caller is a CLI, API, scheduler, or test.

### Plugins never generate project reports

A scanner returns raw traceability data, normalized findings, and scanner metadata. The report layer writes normalized JSON and HTML. CycloneDX generation is treated as an engine-native scanner capability, but the caller chooses the destination and artifact name.

### Normalization is mandatory

Every scanner returns secscan-owned `Finding` objects. Policy and report code must not branch on Trivy, target type, or another engine-specific result shape.

### Tools are adapters

`ImageScanner` and `FilesystemScanner` are target plugins. Trivy is the initial engine adapter used beneath both plugins. A future engine may replace or complement Trivy without changing the registry, CLI request model, policy layer, or report layer.

### Registration is explicit

Built-in scanners are registered explicitly. Dynamic entry points, remote plugins, and untrusted plugin loading remain deferred until a trust, compatibility, and signing model is defined.

## Core contracts

### `ScanRequest`

An immutable request containing the scanner name, target reference or path, timeout, and optional output location.

### `ScanResult`

An immutable result containing the original request, normalized findings, raw engine payload, and scanner metadata.

### `Scanner`

Every scanner provides a stable capability name, description, target help, `scan(request)`, and engine-native SBOM generation.

### `ScannerRegistry`

The registry registers scanner instances, rejects duplicate names, resolves scanners, lists capabilities deterministically, and raises actionable errors for unknown scanners.

## Module responsibilities

### `cli.py`

- parse commands and options
- create `ScanRequest`
- resolve scanners through the registry
- invoke reporting and policy using `ScanResult`
- translate results into documented exit codes

The CLI must not implement target-specific validation or engine subprocess behavior.

### `scanners/image.py`

Own container-image orchestration and delegate image vulnerability and SBOM operations to the Trivy adapter.

### `scanners/filesystem.py`

- expand and resolve the requested path
- reject nonexistent or unreadable targets
- delegate filesystem vulnerability and SBOM operations to the Trivy adapter
- normalize engine output into `ScanResult`

The plugin does not modify the target. Container usage must mount filesystem targets read-only.

### `trivy.py`

- invoke Trivy image and filesystem modes safely
- capture raw JSON
- generate CycloneDX output
- enforce subprocess timeouts
- distinguish scanner failure from vulnerability findings

### `normalize.py`

Convert engine-specific output into stable `Finding` values and calculate severity summaries.

### `policy.py`

Evaluate normalized findings. Policy failure is distinct from scanner or internal failure.

### `report.py`

Write project artifacts from normalized data without rerunning or reinterpreting the scanner.

## Artifact contract

A successful image or filesystem scan produces:

- `trivy.json` — raw engine findings
- `secscan.json` — normalized project-owned findings
- `secscan.cdx.json` — CycloneDX SBOM
- `secscan.html` — self-contained human-readable report

Target type is reflected in the scan request and raw engine data. Artifact names and exit semantics remain stable.

## Exit-code contract

- `0` — scan completed and policy passed
- `1` — input, scanner, artifact, registry, or internal operational failure
- `2` — scan completed successfully but violated policy

A discovered vulnerability is not the same as a broken scan.

## Packaging and CI contract

Every pull request validates:

```text
source modules and scanner subpackages
    -> Ruff, mypy, and pytest
    -> wheel build and manifest verification
    -> clean wheel installation and imports
    -> Docker image build and CLI startup
    -> fixable-critical self-scan
    -> CodeQL
```

Required scanner modules must be verified in the source tree, built wheel, clean installation, and runtime image.

## Security boundaries

### Filesystem targets

- container targets are mounted read-only with `:ro`
- secscan writes only to designated report and cache locations
- secscan does not attempt privilege escalation or bypass host permissions
- unreadable or nonexistent targets fail as operational errors
- sensitive target contents are not copied into normalized reports by design, although raw scanner output must still be handled as security-sensitive data

### Docker socket

Normal image and filesystem scanning do not require `/var/run/docker.sock`.

### Rootless Docker

Docker-managed named volumes are the supported path for report and cache persistence. The project must not require `0777`, `--privileged`, or disabling SELinux.

### Plugin loading

Only trusted built-in plugins are registered. Arbitrary plugin loading is code execution and remains out of scope.

### Supply chain

- base images and scanner versions are pinned
- Python wheels are built and inspected
- CI actions are version-pinned
- release images are scanned
- future release work adds signatures, provenance, and immutable digests

## Coding and design standards

- Python 3.12 is the current runtime baseline.
- Public functions and plugin contracts use type annotations.
- New target integrations implement `Scanner` rather than adding target conditionals to the CLI.
- New engines remain adapters beneath scanner plugins.
- New output formats consume normalized project-owned models.
- Tests accompany new behavior and failure paths.
- Security and cost implications are documented in every sprint and PR.
- Unrelated files are not changed as part of a focused increment.

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
