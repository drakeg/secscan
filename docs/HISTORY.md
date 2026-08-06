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

This scan-level history cannot identify when an individual vulnerability first appeared or was fixed. It therefore does not claim to calculate mean time to remediation; that requires a later finding-level history model.

## Disable recording

Use `--no-history` for an individual scan:

```bash
secscan scan filesystem . --output-dir ./reports --no-history
```

## Stored data

Sprint 5.5 stores scan-level metadata only:

- timestamp
- scanner type and target
- duration
- policy threshold
- severity totals
- report, SBOM, and optional diff paths
- secscan and scanner-engine versions

Detailed findings remain in the normalized report artifacts and are not duplicated in SQLite.

## Schema migrations

The database contains a `schema_migrations` table. secscan applies internal, ordered migrations before reading or writing history. Migration version 1 creates the `scans` table and the target/timestamp index.

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
python -m json.tool ./reports/alpine-trend.json
```

Confirm the JSON series is chronological, contains only `image` / `alpine:3.20` records, and that each signed change equals the latest count minus the oldest count. Use `--scanner ecr` with the exact immutable digest URI when inspecting authenticated ECR history.
