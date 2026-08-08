# SBOM Scanning

secscan accepts CycloneDX JSON plus SPDX 2.2 and 2.3 JSON as first-class SBOM inputs.

## Usage

```bash
secscan scan sbom build.cdx.json \
  --output-dir ./reports \
  --fail-on HIGH
```

The same command accepts SPDX JSON:

```bash
secscan scan sbom build.spdx.json \
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
- identify exactly one supported format: `bomFormat: CycloneDX`, or `spdxVersion: SPDX-2.2` / `SPDX-2.3`
- contain a `components` value that is a list when present for CycloneDX
- contain a `packages` value that is a list when present for SPDX

Malformed or unsupported input exits with code `1`.

## Artifacts

The scanner preserves the existing artifact contract:

- `trivy.json` contains raw Trivy SBOM vulnerability results
- `secscan.json` contains normalized findings and policy metadata
- `secscan.html` contains the browser report
- `secscan.cdx.json` is a byte-for-byte copy of validated CycloneDX input
- `secscan.spdx.json` is a byte-for-byte copy of validated SPDX input
- `secscan.diff.json` is written when `--baseline` is supplied
- `secscan.db` records scan metadata unless `--no-history` is supplied

## Scope

Only CycloneDX JSON and SPDX 2.2/2.3 JSON are supported. SPDX tag/value, YAML, RDF, XML, SPDX 3, CycloneDX XML, package inventory analysis, license analysis, SBOM-to-SBOM package diffing, signing, attestation verification, and cross-source correlation remain out of scope.

## Security

Treat SBOMs as security-sensitive inventory. Mount inputs read-only, restrict report access, and do not include credentials or private registry tokens in SBOM metadata.

## Cost

SBOM ingestion is local and introduces no cloud resources or recurring infrastructure cost.

## Local testing procedure

Run the automated scanner and CLI/service integration tests:

```bash
pytest tests/test_sbom_scanner.py tests/test_cli_sbom.py tests/test_service.py
```

For a manual SPDX smoke test, save a valid SPDX 2.3 JSON document as `build.spdx.json`, then run:

```bash
secscan scan sbom build.spdx.json --output-dir ./reports/spdx --fail-on NONE
python -m json.tool ./reports/spdx/secscan.spdx.json
cmp build.spdx.json ./reports/spdx/secscan.spdx.json
```

Confirm `trivy.json`, `secscan.json`, `secscan.html`, `secscan.spdx.json`, and `secscan.db` exist. The `cmp` command should produce no output and return success. Repeat with a CycloneDX input and confirm the preserved artifact remains `secscan.cdx.json`.

## Package and declared-license inventory

Create a normalized inventory without running Trivy or writing scan history:

```bash
secscan inventory sbom build.cdx.json --output ./reports/secscan.inventory.json
secscan inventory sbom build.spdx.json --output ./reports/secscan.inventory.json
```

The versioned JSON contains source format metadata, deterministically sorted packages, declared license values, package/license coverage totals, and per-license package counts. CycloneDX license IDs, names, and expressions are retained as source-declared strings; SPDX uses `licenseDeclared`. Missing values remain empty and are never inferred.

This output is inventory data, not legal advice or a compliance determination. secscan does not evaluate license compatibility, obligations, concluded licenses, or effective licensing.

Test the inventory path locally:

```bash
pytest tests/test_sbom_inventory.py tests/test_cli_inventory.py
secscan inventory sbom build.spdx.json --output ./reports/secscan.inventory.json
python -m json.tool ./reports/secscan.inventory.json
```

Run the command twice and compare checksums to confirm deterministic output:

```bash
shasum -a 256 ./reports/secscan.inventory.json
secscan inventory sbom build.spdx.json --output ./reports/secscan.inventory.json
shasum -a 256 ./reports/secscan.inventory.json
```
