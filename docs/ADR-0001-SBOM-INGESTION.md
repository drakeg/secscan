# ADR-0001: CycloneDX SBOM Ingestion

> Sprint 15 extends this decision to SPDX 2.2/2.3 JSON. The same scanner and pipeline are reused, while validated SPDX input is preserved as `secscan.spdx.json` rather than the CycloneDX-specific artifact.

## Status

Accepted for Sprint 7.

## Context

secscan already generates CycloneDX SBOMs for image, filesystem, and repository targets. Sprint 7 must ingest an existing SBOM without changing the scanner-neutral policy, baseline, reporting, history, or exit-code layers.

## Decision

Add `SBOMScanner` as a trusted built-in scanner plugin.

The plugin:

- validates a local CycloneDX JSON file
- delegates vulnerability discovery to Trivy `sbom` mode
- normalizes Trivy output into existing `Finding` objects
- returns raw engine output through `ScanResult`
- copies the validated input to the standard `secscan.cdx.json` artifact path

The CLI, report layer, policy engine, comparison engine, and history store remain scanner-neutral and require no SBOM-specific branches.

## Data flow

```text
CycloneDX JSON file
        |
        v
   SBOMScanner validation
        |
        v
   Trivy sbom adapter
        |
        +--> raw Trivy JSON
        v
   existing normalizer
        |
        v
 policy / baseline / reports / history
```

## Security boundaries

- inputs are local files and should be mounted read-only
- JSON is parsed as data only
- unsupported formats fail closed
- SBOM content and generated reports are security-sensitive inventory
- no credentials, remote downloads, or executable plugin loading are introduced

## Consequences

CycloneDX JSON becomes a first-class scan target while the existing artifact and exit-code contracts remain stable. SPDX, signature verification, package intelligence, license analysis, and cross-source correlation remain backlog items.

## Cost

No cloud resources or recurring infrastructure cost are introduced.
