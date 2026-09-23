# Sprint 75 — Reassessment Scheduling Foundation

## Goal

Add an opt-in, local reassessment scheduler for persistent assets. The scheduler must reuse secscan's existing tenant, project, authorization, validation, and job execution boundaries rather than becoming a second way to launch arbitrary scans.

## Scope

- persist reassessment schedules in the existing SQLite state database
- bind every schedule to exactly one tenant and optionally one project
- initially support bounded `daily` and `weekly` cadences only
- schedule only explicitly supported persistent assets with validated scan profiles
- record enabled/paused state, cadence, next run, last attempted run, last successful enqueue, and audit timestamps
- enqueue due reassessments through the existing service job path
- prevent overlapping duplicate executions for one schedule
- allow authorized owner/operator lifecycle actions without exposing stored credentials
- provide deterministic clock injection for tests and restart/misfire behavior

## Security boundaries

- no arbitrary cron expressions, shell commands, URLs, CIDRs, or scanner flags in schedule definitions
- no cross-tenant asset, credential, project, or job access
- project-scoped schedules require the same project operator authorization as an equivalent manual scan
- schedule execution does not elevate the creating user or bypass current ACLs
- disabled/deleted/unavailable assets or credentials fail closed
- one schedule cannot enqueue a second run while its previous scheduled run is still active
- scheduler metadata never returns secret material
- restart recovery is bounded; missed runs do not fan out into an unbounded catch-up burst
- no external scheduler, hosted queue, paid service, or recurring spend

## Initial supported asset boundary

Planning starts with persistent asset types that already have a deterministic existing job path and durable target identity. Implementation must verify those paths before enabling each type; unsupported asset types remain unschedulable rather than falling back to arbitrary target input.

## Misfire and restart policy

- at most one overdue execution may be considered per schedule after restart
- the next run advances from the scheduler's current evaluation time, not by replaying every missed interval
- a failed enqueue is recorded and retried only at a later bounded scheduler evaluation
- clock handling uses timezone-aware UTC values

## Authorization

- tenant owners may create, inspect, pause, resume, and delete tenant schedules
- project operators may manage schedules only for projects where they currently retain operator access
- viewers cannot create or mutate schedules
- authorization is re-evaluated at mutation and execution boundaries where a user-bound permission is required

## Acceptance criteria

1. A valid supported asset can receive one bounded daily or weekly schedule.
2. Schedule persistence survives process restart.
3. Due evaluation is deterministic under an injected UTC clock.
4. A due schedule enqueues through the existing validated job boundary.
5. Two concurrent scheduler evaluations cannot enqueue duplicate active runs for one schedule.
6. Missed intervals do not create an unbounded catch-up burst.
7. Paused schedules never enqueue.
8. Cross-tenant, viewer, revoked project operator, unsupported asset, and unavailable dependency cases fail closed.
9. API/CLI responses contain schedule metadata but no credential secrets.
10. Existing manual scans remain behaviorally unchanged.
11. Python 3.12/3.14, package, Docker/Compose/Trivy, and CodeQL checks remain green.
12. No paid service or recurring spend is introduced.

## Delivery sequence

1. persistence model and deterministic due calculation
2. tenant/project authorization boundary
3. supported asset-to-job adapter
4. atomic due-claim / duplicate-run prevention
5. bounded scheduler loop and restart/misfire behavior
6. lifecycle API/UI surfaces and documentation
7. acceptance/security review
