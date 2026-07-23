# Policy Configuration

secscan policies define a default severity threshold and temporary, auditable suppressions. Policies apply equally to image and filesystem scans.

## Example

```yaml
policy:
  fail_on: HIGH

suppressions:
  - vulnerability: CVE-2026-12345
    package: openssl
    reason: Vendor patch is scheduled for the next maintenance window
    expires: 2026-09-30
```

Run a scan with the policy:

```bash
secscan scan image alpine:3.20 --policy policy.yaml
```

Inside Docker, mount the policy read-only:

```bash
docker run --rm \
  -v "$PWD/policy.yaml:/config/policy.yaml:ro" \
  -v secscan-reports:/reports \
  -v secscan-cache:/cache \
  secscan:dev scan image alpine:3.20 \
    --policy /config/policy.yaml \
    --output-dir /reports
```

## Threshold precedence

1. `--fail-on` explicitly supplied on the command line
2. `policy.fail_on` from the YAML file
3. built-in default of `CRITICAL`

Valid thresholds are `NONE`, `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

## Suppression rules

Each suppression requires:

- `vulnerability`: exact vulnerability identifier
- `reason`: non-empty audit explanation
- `expires`: ISO date in `YYYY-MM-DD` format

`package` is optional. When supplied, both the vulnerability and package must match.

A suppression is active through its expiration date. It is ignored beginning the following day. Expired rules remain in the policy file but do not hide findings.

## Reporting behavior

The standard findings remain in the report for traceability. `secscan.json` includes a `policy` object containing:

- effective `fail_on` threshold
- active finding count
- suppressed vulnerability, package, reason, and expiration details

Only active, unsuppressed findings determine policy failure and exit code `2`.

## Security guidance

- Keep policy files in source control when they contain no secrets.
- Require a meaningful reason and short expiration period.
- Review suppressions before renewal rather than extending them automatically.
- Never use suppressions to conceal scanner errors or missing scan coverage.
