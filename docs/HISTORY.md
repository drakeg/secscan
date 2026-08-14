# Local Scan History

secscan can record metadata for every successfully completed scan in a local SQLite database. History is local by default and does not require AWS or another external service.

## Default database

Container commands default to:

```text
/reports/secscan.db
```

Because `/reports` is normally a persistent Docker volume, the history database survives disposable scanner containers.

For local Python use, select an explicit path:

```bash
secscan scan image alpine:3.20 \
  --output-dir ./reports \
  --history-db ./reports/secscan.db
```

## List scans

```bash
secscan history --history-db ./reports/secscan.db
```

Limit the output:

```bash
secscan history --history-db ./reports/secscan.db --limit 10
```

## Show one scan

```bash
secscan show 42 --history-db ./reports/secscan.db
```

The command displays scanner type, target, timestamp, duration, policy threshold, severity totals, artifact paths, and scanner versions.

## Summarize a trend

Compare the most recent scans from one exact scanner and target cohort:

```bash
secscan trends \
  --history-db ./reports/secscan.db \
  --scanner image \
  --target alpine:3.20 \
  --limit 20
```

Write the same result as versioned JSON for automation:

```bash
secscan trends \
  --history-db ./reports/secscan.db \
  --scanner image \
  --target alpine:3.20 \
  --limit 20 \
  --output ./reports/alpine-trend.json
```

The command requires between 2 and 100 matching scans. It selects the newest matching records and presents them oldest first. `change_since_oldest` is the signed difference `latest - oldest` for each severity; a negative number means fewer recorded findings. Trend generation is read-only with respect to scan records.

## Compare latest finding observations

New scans retain normalized finding fingerprints. Compare the two latest finding-enabled scans from one exact cohort:

```bash
secscan finding-changes \
  --history-db ./reports/secscan.db \
  --scanner image \
  --target alpine:3.20 \
  --output ./reports/alpine-finding-changes.json
```

The report classifies stable fingerprints as `new`, `resolved`, or `unchanged` and identifies both source scan records. It requires two finding-enabled scans. A completed zero-finding scan is a valid observation and resolves findings from the previous matching scan.

Legacy records are not interpreted as zero-finding scans. secscan cannot know whether their old report paths still exist or are unchanged, so it does not backfill them automatically. This latest-transition report also does not claim first-seen time or mean time to remediation; trustworthy episode timing remains a later increment.

## Disable recording

Use `--no-history` for an individual scan:

```bash
secscan scan filesystem . --output-dir ./reports --no-history
```

## Stored data

Each new scan stores scan-level metadata plus normalized finding identity fields:

- timestamp
- scanner type and target
- duration
- policy threshold
- severity totals
- report, SBOM, and optional diff paths
- secscan and scanner-engine versions
- stable fingerprint, vulnerability ID, package, installed/fixed version, severity, finding target, and package type

Titles, URLs, publication dates, raw scanner payloads, and policy evaluation remain in report artifacts rather than SQLite. Protect both the database and reports as security-sensitive inventory.

## Schema migrations

The database contains a `schema_migrations` table. secscan applies internal, ordered migrations before reading or writing history. Migration version 1 creates aggregate scan history. Version 2 adds finding observations and marks legacy rows as not recorded; it neither reads old report paths nor invents empty observations.

## Operational notes

- Recordings occur only after report and SBOM generation succeeds.
- History failures are operational errors and return exit code `1`.
- Protect the database as security-sensitive inventory.
- Back up the database together with the reports it references.
- Moving report files does not rewrite paths already stored in history.

## Local testing procedure

Run the automated history and CLI tests:

```bash
pytest tests/test_history.py tests/test_cli_history.py
```

For a manual test, create at least two scans of the same scanner and target using one database, then generate both console and JSON trends:

```bash
secscan scan image alpine:3.20 --output-dir ./reports/run-1 --history-db ./reports/secscan.db --fail-on NONE
secscan scan image alpine:3.20 --output-dir ./reports/run-2 --history-db ./reports/secscan.db --fail-on NONE
secscan trends --history-db ./reports/secscan.db --scanner image --target alpine:3.20 --limit 20
secscan trends --history-db ./reports/secscan.db --scanner image --target alpine:3.20 --limit 20 --output ./reports/alpine-trend.json
secscan finding-changes --history-db ./reports/secscan.db --scanner image --target alpine:3.20 --output ./reports/alpine-finding-changes.json
python -m json.tool ./reports/alpine-trend.json
python -m json.tool ./reports/alpine-finding-changes.json
```

Confirm the trend series is chronological and exact-cohort. In finding changes, confirm the scan IDs are the two latest matching observations and manually cross-check new, resolved, and unchanged entries against their `secscan.json` reports. Run a third scan against another target and confirm it does not affect the result. Use `--scanner ecr` with the exact immutable digest URI for authenticated ECR history.
