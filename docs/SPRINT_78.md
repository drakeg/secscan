# Sprint 78 — Reassessment Scheduler Correctness

## Goal

Ensure one safely failed scheduled reassessment cannot delay other due schedules or make scheduler progress ambiguous.

## Security and correctness boundaries

- Authorization and project access are re-evaluated immediately before every scheduled submission.
- A revoked, disabled, invalid, or otherwise failed claimed schedule is recorded as attempted and never enqueued.
- A failed claimed schedule does not stop the same bounded scheduler tick from considering later due work.
- A tick still stops promptly when no due schedule exists.
- Existing claim-token, cadence, retry, tenant, and project isolation semantics remain unchanged.
- Scheduler work remains bounded to the configured per-tick limit; no catch-up burst is introduced.
- No hosted service, paid dependency, or recurring infrastructure cost is introduced.

## Increment 1 — Explicit claim outcomes

Separate “no schedule was due” from “a schedule was claimed but failed closed.” The scheduler counts bounded claimed attempts and continues after safe failures, while still stopping when the store reports no due work.

## Acceptance

- successful scheduled submissions continue to enqueue and advance cadence
- failed claimed schedules remain fail-closed and record their attempt
- a failed first claim cannot postpone a healthy later due schedule to the next interval
- no-due-work still terminates the tick immediately
- tick limits remain bounded from 1 through 100
- Python/package/container/Compose/CI/CodeQL gates remain green
- recurring infrastructure cost remains $0
