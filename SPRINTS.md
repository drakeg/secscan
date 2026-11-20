# Secscan Sprint Plan

**Product goal:** Deliver a self-hosted, operator-friendly vulnerability assessment and evidence workflow for SMB IT teams and small managed service providers. Preserve the complete historical sequence in [docs/REMAINING_SPRINTS.md](docs/REMAINING_SPRINTS.md); this file is the concise current sprint index, not a restart.

## Completed

- Sprints 0–80: completed security scanning, CLI/API/web operations, tenant/project isolation, policy and release workflows, and extensive authentication and CI hardening. See [detailed sprint records](docs/REMAINING_SPRINTS.md).
- Sprint 81 increments 1–4: immutable ECR → ECS/EKS workload association (#218), opt-in report binding (#219), tenant-scoped report context reads (#220), persisted evidence scope checks (#221).
- Sprint 81 increment 5, **PR #223**: operator-provided ECS/EKS tenant-partitioned inventory ingestion; checks green as of standards audit but merge pending. Treat such snapshots as unverified. Do not mark delivered until merged.

## Current — Sprint 81: Safe cloud context foundations

**Goal:** Make workload context trustworthy enough for future vulnerability report enrichment without confusing an uploaded snapshot with authenticated AWS discovery.

**In scope:** Complete #223; review tenant/session authorization and bounded persistence; document source provenance; add regression tests for cross-tenant isolation, malformed snapshots, and lifecycle/restart behavior.

**Acceptance:** Every persisted snapshot is scoped to the authenticated tenant; invalid input cannot replace valid inventory; only verified provenance may be used to modify vulnerability priority or assert deployment. CI/CodeQL green. No new paid infrastructure.

**Explicitly deferred:** Claims of internet exposure, effective IAM privilege, runtime execution, automatic cloud account ownership, paid graph services and production auto-remediation.

## Candidate Sprint 82 — Verified discovery linkage

**Goal:** Bind approved AWS discovery configuration and tenant-owned credentials to inventory provenance; prevent operator-provided snapshots from being treated as cloud-verified.

**Acceptance:** Evidence describes who/what/when performed discovery, remains tenant-scoped, and fails closed when stale or inaccessible. Regression tests show no cross-tenant linkage. No paid dependencies.

## Candidate Sprint 83 — SMB remediation workflow

**Goal:** Provide a small, useful web flow: pick an authorized scan, review prioritized findings and evidenced workload references, export a customer-readable action report.

**Acceptance:** An operator can demonstrate a complete scan-to-remediation workflow on a local Docker Compose test instance; no unsupported exposure assertions, tenant data leaks, or manual JSON editing required.

## Candidate Sprint 84 — Pilot readiness

**Goal:** Simple installation, first-run checklist, bounded demo data and feedback collection; verify installation and end-to-end workflows with a real pilot before charging.

**Acceptance:** Reproducible demo, verified deployment/security defaults, clear pricing experiment and evidence of customer feedback (not invented).

Update sprint statuses when PRs merge and tests actually pass. Maintain the detailed per-sprint record in `docs/SPRINT_81.md` and successors.
