# ADR-0002: Typed and Explainable Policy v2 Rules

## Status

Accepted for Sprint 8 implementation.

## Context

The original policy engine supports one global severity threshold and temporary exact-CVE suppressions. That remains useful, but it cannot express narrower remediation requirements such as stricter handling for a critical package, findings with an available fix, or vulnerabilities older than an allowed period.

The policy engine must remain scanner-neutral and existing policy files must continue to work unchanged.

## Decision

Add an optional top-level `rules` list containing typed `PolicyRule` values. A rule may combine exact vulnerability, package, severity, fix-availability, and maximum-age conditions. All configured conditions must match the same normalized finding.

The normalized `Finding` model gains an optional `published_date`. It is populated from Trivy metadata when available and omitted from serialized reports when unavailable, preserving the existing report shape.

Evaluation order is:

1. Load and strictly validate the policy.
2. Apply active suppressions.
3. Evaluate every ordered Policy v2 rule against active findings.
4. Evaluate the effective global severity threshold.
5. Return exit code `2` when either the global threshold or a Policy v2 rule fails.

Every rule match is retained in `secscan.json` with the rule number, finding identity, rule threshold, and explanation.

## Validation

Unknown keys fail closed. Rules require at least one match condition. Invalid severities, negative ages, non-boolean fix conditions, and conflicting duplicate match definitions are operational errors.

## Consequences

- Existing policy files remain valid.
- Policy decisions become more targeted and auditable.
- Age rules depend on upstream publication metadata and do not match when that metadata is absent.
- Rules remain exact-match only; patterns, risk enrichment, and remote policy distribution remain backlog items.
- No external service or recurring infrastructure cost is introduced.
