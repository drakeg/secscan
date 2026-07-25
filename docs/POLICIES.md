# Policy Configuration

secscan policies define a default severity threshold, temporary auditable suppressions, and optional typed rules. Policies apply equally to image, filesystem, repository, and SBOM scans.

## Backward compatibility

Existing policy files remain valid. The `policy.fail_on` threshold and top-level `suppressions` format are unchanged. Policy v2 adds an optional top-level `rules` list.

## Example

```yaml
policy:
  fail_on: CRITICAL

suppressions:
  - vulnerability: CVE-2026-12345
    package: openssl
    reason: Vendor patch is scheduled for the next maintenance window
    expires: 2026-09-30

rules:
  - package: openssl
    fix_available: true
    fail_on: HIGH
    reason: Patchable OpenSSL vulnerability

  - severity: HIGH
    max_age_days: 30
    fail_on: HIGH
    reason: High vulnerability older than 30 days
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

The global threshold and Policy v2 rules are evaluated independently. A scan fails with exit code `2` when either the effective global threshold or any matching Policy v2 rule fails.

## Suppression rules

Each suppression requires:

- `vulnerability`: exact vulnerability identifier
- `reason`: non-empty audit explanation
- `expires`: ISO date in `YYYY-MM-DD` format

`package` is optional. When supplied, both the vulnerability and package must match.

A suppression is active through its expiration date. It is ignored beginning the following day. Suppressions are applied before Policy v2 rules, so an actively suppressed finding does not create a rule match.

## Policy v2 rules

Each rule requires at least one match condition and may use any combination of:

- `vulnerability`: exact vulnerability identifier
- `package`: exact package name
- `severity`: exact normalized severity
- `fix_available`: `true` when a non-empty fixed version must exist, or `false` when no fix must be available
- `max_age_days`: match only when the published vulnerability age is greater than this non-negative number of days

Each rule also supports:

- `fail_on`: minimum finding severity that causes this rule to fail; defaults to `HIGH`
- `reason`: explanation written to policy metadata; defaults to a generated rule description

All specified match conditions must match. Rules are evaluated in file order for reporting, but every matching rule is retained in `secscan.json`.

Age rules fail closed with respect to missing metadata: if Trivy does not provide a usable publication date, an age condition does not match that finding.

## Validation

Policies reject:

- unknown root, policy, suppression, or rule keys
- unsupported severities
- negative or non-integer `max_age_days`
- non-boolean `fix_available`
- rules without a match condition
- duplicate match conditions with conflicting `fail_on` values
- malformed dates or missing suppression audit fields

Invalid policies are operational errors and return exit code `1`.

## Reporting behavior

The standard findings remain in the report for traceability. `secscan.json` includes a `policy` object containing:

- effective `fail_on` threshold
- active finding count
- suppressed vulnerability, package, reason, and expiration details
- every Policy v2 rule match, including rule number, vulnerability, package, threshold, and reason

Only active, unsuppressed findings participate in global threshold and Policy v2 rule failure evaluation.

## Security guidance

- Keep policy files in source control when they contain no secrets.
- Require meaningful reasons for suppressions and important rules.
- Use short suppression expiration periods.
- Review rule matches in `secscan.json` rather than relying only on the process exit code.
- Never use suppressions to conceal scanner errors or missing scan coverage.
