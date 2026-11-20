# Security policy

Secscan scans sensitive infrastructure. Only assess assets you own or are authorized to test. Do not include credentials, private reports, customer identifying data or live exploit details in public issues.

## Reporting security issues

Use [GitHub's private vulnerability reporting flow](https://github.com/drakeg/secscan/security/advisories/new) if enabled. If that flow is unavailable, ask maintainers for a private reporting channel without posting exploit details publicly. No disclosure email or guaranteed response SLA has been verified.

## Security boundaries

- Authentication and tenant authorization are mandatory for customer-facing workflows; never trust a submitted tenant ID or operator-provided AWS snapshot as proof of account ownership.
- Prefer immutable image targets, least-privilege cloud roles, bounded requests, read-only mounts, non-root containers and pinned scanner sources.
- Report context must distinguish observed configuration from internet exposure, running workloads and effective privilege.
- Regressions affecting tenant isolation, credential protection or scanning authorization are P0 and supersede normal sprint work.
- Track fixes in reviewable PRs with regression tests. Require CI and CodeQL checks to pass before release.

See [docs/ENGINEERING_STANDARDS.md](docs/ENGINEERING_STANDARDS.md) and [AGENTS.md](AGENTS.md).
