# Sprint 48 — Local EPSS Enrichment

## Goal

Add deterministic, opt-in FIRST EPSS prioritization metadata to vulnerability reports using an operator-supplied daily CSV, while preserving CISA KEV as an independent signal and keeping scans free of live threat-intelligence network dependencies.

## Stories and acceptance criteria

- `SECSCAN_EPSS_CSV` accepts only an existing absolute path to an uncompressed local CSV.
- EPSS comment lines beginning with `#` are ignored and the data header must be exactly `cve,epss,percentile`.
- CVE identifiers are matched case-insensitively by exact normalized CVE ID.
- duplicate CVEs, malformed rows, non-finite values, or scores/percentiles outside 0–1 fail closed.
- matched findings gain an `epss` object containing numeric `score` and `percentile` fields.
- reports expose EPSS enrichment status, scored-finding count, source-entry count, and maximum observed EPSS score.
- HTML reports show EPSS probability and percentile without inventing a universal remediation threshold.
- existing CISA KEV enrichment remains independent and unchanged.
- Compose passes both `SECSCAN_KEV_CATALOG` and `SECSCAN_EPSS_CSV` into service and CLI containers so documented local enrichment works.

## Security and correctness boundaries

- no EPSS API requests or automatic downloads occur during scans.
- score-file freshness is operator-controlled and must not be represented as real-time threat intelligence.
- EPSS does not rewrite CVSS/Trivy severity, finding fingerprints, suppression behavior, or policy exit codes.
- no default EPSS remediation threshold is introduced; FIRST documents that appropriate thresholds depend on remediation capacity, risk tolerance, and asset context.
- no credentials, paid services, cloud resources, or new network exposure are introduced.
- malformed enrichment data fails closed rather than silently producing partial or misleading prioritization.

## Operations and cost

FIRST publishes EPSS scores daily and makes them freely available. Operators may place the uncompressed daily CSV beneath the Compose workspace and configure an in-container path such as `/workspace/epss.csv`.

Current and projected recurring secscan infrastructure/service cost remains **$0**.

## Validation

Before merge:

- Python 3.12 and 3.14 preflight pass.
- EPSS parser/enrichment tests cover valid data, comment lines, missing paths, invalid headers, duplicate CVEs, and invalid probabilities.
- Docker/Compose service smoke and authenticated Linux-host fixture pass.
- Trivy fixable-critical self-scan passes.
- CodeQL workflow and the separate GitHub code-scanning check pass on the exact PR head.
