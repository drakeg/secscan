# SBOM Scanning

Sprint 7 adds CycloneDX JSON SBOMs as a first-class secscan input.

## Usage

```bash
secscan scan sbom build.cdx.json \
  --output-dir ./reports \
  --fail-on HIGH
```

The SBOM scanner validates the input, invokes Trivy SBOM mode, normalizes vulnerability findings, applies the existing policy and baseline pipeline, records scan history, and writes the standard report artifacts.

## Docker

Mount the SBOM read-only and persist reports and the vulnerability database cache:

```bash
docker run --rm \
  -v "$PWD/build.cdx.json:/input/build.cdx.json:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan sbom /input/build.cdx.json \
    --output-dir /reports \
    --fail-on HIGH
```

## Validation

The input must:

- be a readable regular file
- contain valid JSON
- have `bomFormat` set to `CycloneDX`
- contain a `components` value that is a list when present

Malformed or unsupported input exits with code `1`.

## Artifacts

The scanner preserves the existing artifact contract:

- `trivy.json` contains raw Trivy SBOM vulnerability results
- `secscan.json` contains normalized findings and policy metadata
- `secscan.html` contains the browser report
- `secscan.cdx.json` is a copy of the validated input SBOM
- `secscan.diff.json` is written when `--baseline` is supplied
- `secscan.db` records scan metadata unless `--no-history` is supplied

## Scope

This sprint supports CycloneDX JSON ingestion only. SPDX input, package inventory analysis, license analysis, SBOM-to-SBOM package diffing, signing, attestation verification, and cross-source correlation remain backlog items.

## Security

Treat SBOMs as security-sensitive inventory. Mount inputs read-only, restrict report access, and do not include credentials or private registry tokens in SBOM metadata.

## Cost

SBOM ingestion is local and introduces no cloud resources or recurring infrastructure cost.
