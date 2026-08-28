# Sprint 52 — Public Product Experience and Account Plans

## Goal

Let prospective customers understand secscan before authentication, then choose an account tier during registration and manage that tier after sign-in without weakening protection around the scanner workspace or APIs.

## Stories

### Public product landing

- `GET /` is accessible without authentication.
- The landing page explains major secscan capabilities, supported assessment categories, prioritization, and plan choices.
- Anonymous visitors can choose Sign in, Register, or compare plans without being redirected to authentication first.
- The actual scanner workspace moves to protected `GET /app`.

### Plan-aware registration

- Registration requires an explicit `free` or `professional` choice.
- The chosen plan is persisted on the account.
- Existing accounts migrate deterministically to `free`.
- Re-running the migration is safe.

### Account plan management

- Signed-in users can view `/account/plan` and the plan API.
- Signed-in users can change between Free and Professional during the preview phase.
- The UI states clearly that Professional billing is not connected and no charge is created by selecting the preview tier.

### Free-tier boundary

- Core scanning/dashboard functionality remains available to authenticated Free accounts.
- Encrypted reusable SSH credential APIs and authenticated Linux-host web job submission require Professional.
- The restriction is enforced server-side, not only hidden in browser markup.
- CLI behavior remains unchanged; this sprint scopes plan entitlement to customer/account web workflows.

## Initial plan definitions

### Free

Evaluation/basic use with core repository, image, filesystem, SBOM, basic network scanning, normalized findings/history, KEV/EPSS prioritization when configured, and persistent asset inventory.

### Professional

Everything in Free plus authenticated-host web workflows, encrypted reusable SSH credential profiles, and the intended path for advanced asset, integration, and team capabilities.

Professional is a preview access tier in this sprint. No payment processor, card collection, recurring charge, invoice, or external billing account is created.

## Security and correctness boundaries

- `/app` and non-public application/API routes remain session/bearer protected.
- `/` becomes public intentionally; the change does not make scan history, findings, credentials, or asset APIs public.
- Plan selection is allow-listed to two exact values.
- Existing accounts default to Free during migration.
- Free-tier host-workflow restrictions are checked server-side against the authenticated session.
- No payment credentials or billing secrets are collected.
- No tenant-isolation claims are made; tenant/project isolation remains a later sprint.
- No unrelated scanner, policy, fingerprint, or report behavior changes.

## Cost

Current and projected recurring secscan service cost remains **$0** for this sprint. A future billing-provider sprint must document provider fees and cloud/service costs before activation.

## Validation

- public `/` regression test
- anonymous `/login` and `/register` regression tests
- protected `/app` regression test
- plan-required registration test
- existing-account Free migration and repeat-migration test
- plan upgrade test
- server-side Free/Professional entitlement test
- Ruff, mypy, pytest, wheel verification, clean installation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and separate GitHub code-scanning check must pass before merge
