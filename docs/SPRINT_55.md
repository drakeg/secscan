# Sprint 55 — Authenticated Web/API DAST Submission

## Goal

Expose the bounded `web-dast` scanner through the existing authenticated service and browser workspace without weakening the scanner controls established in Sprint 54.

## Included

- Add `web-dast` to the typed `/api/v1/jobs` scanner allow-list.
- Require an explicit `web_authorized=true` acknowledgement before a web DAST job can be queued.
- Re-run `validate_web_target()` server-side before queuing so browser-side changes cannot bypass URL restrictions.
- Preserve normal job history, artifact, policy, baseline, timeout, and reporting behavior.
- Add `web-dast` as a job-history filter value.
- Add a browser scanner option with a dedicated authorization checkbox and explicit URL placeholder.
- Keep the browser submission payload bounded to the existing job fields plus `web_authorized`.
- Keep Web DAST in the Free/core scanning tier for this increment; no new Professional entitlement is introduced.

## Security boundaries

The service accepts one explicit HTTP/HTTPS URL only. Sprint 54 validation still rejects embedded credentials, fragments, missing hosts, invalid ports, non-HTTP schemes, and overlong targets. The browser cannot submit arbitrary Nuclei arguments, template paths, cookies, custom headers, target lists, callback services, or crawler settings. Authorization acknowledgement is checked server-side and is not forwarded as a scanner CLI argument.

All `/api/v1/*` authentication behavior remains unchanged. When an API token is configured, the existing bearer-token middleware continues to protect job submission. In the full service, existing session authentication also protects the workspace/API path.

## Cost

No paid service, cloud resource, or recurring cost is introduced. Projected recurring secscan service cost remains **$0**.

## Acceptance criteria

- Unauthorized `web-dast` submissions fail with HTTP 422.
- Invalid or credential-bearing URLs fail with HTTP 422 even when authorization is acknowledged.
- Authorized valid submissions queue through the normal job runner as `scan web-dast <url>`.
- Authorization state is not passed to the CLI runner.
- `web-dast` can be filtered in job history.
- Browser UI exposes the scanner only with a dedicated authorization acknowledgement.
- Python 3.12/3.14 quality, package integrity, Docker/Compose smoke, Trivy, CodeQL workflow, and separate GitHub Advanced Security CodeQL checks remain green.
