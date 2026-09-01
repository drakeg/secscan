# Sprint 61 — Bounded GitHub Issue Export

## Goal

Allow an operator to turn one completed `secscan.json` report into one reviewable GitHub issue without making outbound delivery automatic or exposing a token in command history.

## Scope

- CLI-only `secscan export github-issue`
- supported secscan report schemas `1.0`, `1.1`, and `1.2`
- exact public GitHub `OWNER/REPOSITORY` destinations
- one deterministic summary issue containing at most 50 findings
- offline JSON preparation by default
- one explicit POST only when `--submit` is supplied
- a local export/receipt containing the request and returned issue number/URL

## Security and operational boundaries

- The API origin is fixed to `https://api.github.com`; user-controlled hosts and GitHub Enterprise URLs are not accepted.
- The destination path is validated before request construction.
- The fine-grained token is read only from `SECSCAN_GITHUB_ISSUES_TOKEN`, never from a CLI argument.
- Tokens are not persisted, printed, placed in the issue body, or copied into error messages.
- Offline preparation makes no network request and requires no token.
- Submission performs one content-creation request with a 30-second timeout and no automatic retry.
- Findings are deterministically ordered and capped at 50; the issue states how many were omitted.
- The command does not create labels, assignees, milestones, comments, multiple issues, or deduplication searches.
- Web/API submission, background queues, automatic triggers, Jira, Slack, ServiceNow, SIEM, and GitHub Enterprise remain out of scope.

## Cost

This feature adds no secscan infrastructure or recurring service. Offline preparation is entirely local. Optional live submission uses the destination repository owner's existing GitHub account and is subject to GitHub API/content-creation limits, but secscan introduces no paid GitHub plan requirement.

## Acceptance criteria

- malformed reports, unsupported schemas, invalid findings, and ambiguous repository paths fail closed
- dry-run preparation succeeds without a credential or network call
- the prepared issue has deterministic title, counts, ordering, and truncation evidence
- submission requires both `--submit` and a non-empty environment token
- the request uses the fixed GitHub API origin, recommended media type, pinned API version, and bounded timeout
- HTTP/network/malformed-response failures return operational exit code `1` without secret leakage
- the receipt records only non-secret request content plus the returned issue number and URL
- wheel verification includes the integration module
- copyable automated, offline local, and optional live test procedures are documented
- repository preflight, CI, container smoke, and CodeQL pass before merge

See [GitHub Issue Export](GITHUB_ISSUES.md) for operator procedures.
