# Sprint 50 — Persistent Asset Inventory and Reassessment Foundation

## Goal

Create durable first-class asset records from secscan service history so operators can reason about targets as assets rather than reconstructing them from individual jobs.

## Stories and acceptance criteria

- assets are identified deterministically by exact `scanner` + `target` identity
- asset records persist in the existing local SQLite service database
- asset records include first seen, last seen, latest job ID, and scan count
- existing service job history is reconciled into assets without destructive migration
- repeated reconciliation is idempotent
- `GET /api/v1/assets` returns newest-seen assets with a bounded limit
- `GET /api/v1/assets/{asset_id}` returns one asset or 404
- asset routes are mounted before the root StaticFiles catch-all
- no existing job, scanner, policy, baseline, auth, or report semantics change
- wheel-integrity validation includes the asset modules
- Python 3.12/3.14 preflight, Docker/Compose smoke, authenticated Linux fixture, Trivy self-scan, CodeQL workflow, and separate GitHub code-scanning checks are green before merge

## Security and correctness boundaries

Asset identity is exact and deterministic; this sprint does not merge aliases, normalize unrelated hostnames, or infer ownership. Asset APIs are read-only and remain behind the existing service authentication boundary. Reconciliation reads only the local service job database and makes no network calls.

Deleting a historical job is not defined as deleting an asset in this sprint. Asset lifecycle, archival, ownership, labels, scheduling, and tenant isolation remain future work.

## Cost

Current and projected recurring secscan infrastructure/service cost remains **$0**.

## Out of scope

- automatic or scheduled reassessment
- asset deletion or archival
- user-defined tags/labels
- asset ownership or tenancy
- alias/canonical-host merging
- cloud discovery import
- Windows assessment
