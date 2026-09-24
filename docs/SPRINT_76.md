# Sprint 76 — Security Boundary Hardening

## Goal

Harden reassessment persistence and execution boundaries identified during Sprint 75 review before adding new feature surface.

## Scope

- upgrade-safe reassessment schema migration
- strict remote-repository validation for scheduled repository assets
- strict claim-token completion semantics
- execution-time authorization re-evaluation
- safe project association before scheduled execution
- regression coverage for migration, revocation, concurrency, and restart behavior

## Explicitly out of scope

- new scanner types or scheduling cadences
- arbitrary cron expressions
- hosted queues or external schedulers
- new cloud services or paid infrastructure
- broad UI redesign

## Security requirements

1. Existing databases upgrade without data loss or manual recreation.
2. Scheduled repository reassessment cannot turn a persisted local path into recurring filesystem access.
3. A claimed schedule cannot be completed or released by a caller lacking its matching claim token.
4. Disabled/deleted users and revoked project operators cannot retain historical execution authority.
5. Tenant/project ownership is checked using current persisted state.
6. A project-scoped scheduled job cannot start execution before its required project association is safely established.
7. Failure remains bounded and auditable without catch-up bursts or silent authorization bypass.
8. Secrets and internal claim tokens remain absent from public metadata.

## Acceptance criteria

- migration regression starts from the pre-claim Sprint 75 schema and upgrades in place
- tenant-level NULL-project uniqueness remains enforced after upgrade
- local repository paths are rejected by the reassessment adapter
- valid remote HTTPS repository targets remain supported
- stale, absent, and incorrect claim tokens cannot complete an active claim
- revoked/disabled execution authority fails closed before job submission
- project association failure cannot leave a runnable orphaned project job
- existing manual scans remain unchanged
- Python, package, Docker/Compose, CI, and CodeQL gates remain green
- recurring infrastructure cost remains $0

## Delivery sequence

1. persistence migration and claim integrity
2. repository target hardening
3. execution-time authorization
4. project-aware enqueue ordering
5. acceptance/security review and roadmap closeout

## Increment 1 — persistence migration and claim integrity

Reassessment startup now detects pre-claim schedule tables and adds the claim token/expiry columns idempotently before creating claim-dependent indexes. Existing schedule rows are preserved. Attempt completion now distinguishes an unclaimed schedule from an actively claimed schedule: passing no token can complete only an unclaimed row, while an active claim requires the exact matching token. Regression coverage constructs the older schema directly and verifies in-place upgrade plus failed tokenless completion of an active claim.
