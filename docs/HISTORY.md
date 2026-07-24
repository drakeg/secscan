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
