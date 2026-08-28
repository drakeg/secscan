# Sprint 46 — Local CISA KEV Enrichment

## Goal

Make secscan findings more actionable by marking CVEs that appear in a locally supplied CISA Known Exploited Vulnerabilities catalog, without introducing a live network dependency or paid service.

## Stories

1. As an operator, I can opt in to KEV enrichment by providing an absolute local CISA KEV JSON path through `SECSCAN_KEV_CATALOG`.
2. As an operator, secscan reports show whether each CVE is known exploited and surface CISA due date, required action, and known ransomware campaign use.
3. As a security reviewer, I can verify enrichment fails closed for malformed, duplicate, or incomplete KEV data and never changes vulnerability identity or severity.

## Acceptance criteria

- KEV enrichment is disabled by default
- scans never download the KEV catalog themselves
- the configured catalog path must be an existing absolute JSON file
- the catalog root and vulnerability records are strictly validated
- duplicate CVE identifiers are rejected
- `knownRansomwareCampaignUse` accepts only CISA's `Known` or `Unknown` values
- matching is exact and case-insensitive on CVE identifier
- enriched JSON reports include `known_exploited` plus bounded KEV metadata for matches
- report summary includes `known_exploited` count when enrichment is enabled
- HTML reports include a CISA KEV column and known-exploited summary card
- non-matching findings remain normal findings and are explicitly marked `known_exploited: false`
- existing policy, baseline fingerprinting, scanner findings, history identity, and severity values remain unchanged
- tests cover matching, non-matching, disabled behavior, malformed input, duplicate CVEs, and invalid ransomware status
- Python 3.12/3.14 preflight, container/Compose smoke tests, Trivy self-scan, CodeQL workflow, and separate GitHub code-scanning checks are green before merge

## Security and operational boundaries

This sprint performs no HTTP requests and introduces no cloud or SaaS dependency. Catalog freshness is an operator responsibility. A stale catalog can under-report known exploitation, so reports identify enrichment as enabled but do not claim the local catalog is current.

The catalog is treated as untrusted local input. Enrichment adds prioritization metadata only; it does not alter finding fingerprints, severity, suppression, policy outcome, remediation execution, or target access.

## Cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**

## Out of scope

- automatic KEV downloads or scheduled refresh
- EPSS scoring
- CVSS rescoring
- remediation automation
- policy rules based on KEV status
- hosted threat-intelligence services
- catalog signature verification
