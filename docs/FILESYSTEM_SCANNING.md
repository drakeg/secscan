# Filesystem Scanning

Use the built-in filesystem scanner to inspect a local project, extracted container filesystem, mounted image, or other readable directory.

## Local installation

```bash
secscan scan filesystem . --output-dir ./reports --fail-on HIGH
```

## Docker

Mount the scan target read-only and persist reports and the Trivy database cache separately:

```bash
docker volume create secscan-reports
docker volume create secscan-cache

docker run --rm \
  -v "$PWD:/scan:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan filesystem /scan \
    --output-dir /reports \
    --fail-on CRITICAL
```

## Behavior

A successful scan produces `trivy.json`, `secscan.json`, `secscan.cdx.json`, and `secscan.html`.

The scanner resolves the target path and rejects nonexistent or unreadable paths. It does not attempt to elevate privileges or bypass host permissions. The target should be mounted read-only; secscan writes only to the configured report and cache locations.

Exit codes remain consistent across scanner types:

- `0` — scan completed and policy passed
- `1` — target, scanner, artifact, or internal operational failure
- `2` — scan completed but violated the configured severity threshold
