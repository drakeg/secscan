# Finding Baselines and Comparison

Sprint 5 adds comparison of a current scan against a previous normalized `secscan.json` report.

## Usage

```bash
secscan scan image alpine:3.20 \
  --baseline previous/secscan.json \
  --output-dir reports
```

When `--baseline` is supplied, secscan writes the normal scan artifacts plus:

- `secscan.diff.json` — findings classified as `new`, `resolved`, or `unchanged`

## Fingerprint contract

A finding fingerprint is derived from stable identity fields:

- vulnerability ID
- package name
- scanner target
- package type

Installed version, fixed version, severity, title, and advisory URL are intentionally excluded so metadata changes do not create a false new finding.

## Classification

- `new` — present in the current scan but absent from the baseline
- `resolved` — present in the baseline but absent from the current scan
- `unchanged` — present in both reports

The comparison is informational in Sprint 5. Existing YAML policy evaluation and exit codes remain based on the current scan's active findings.

## Validation

The baseline must be valid JSON and contain a top-level `findings` list. Invalid or missing baseline files are operational errors and return exit code `1`.

## Security and privacy

Baseline and comparison reports may contain package and vulnerability inventory. Treat them as security-sensitive artifacts and avoid publishing them unintentionally.

## Cost

Comparison runs locally and introduces no cloud resources or recurring infrastructure cost.
