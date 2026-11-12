# Issue #209 — Immutable ECR/workload association increment

## Goal and outcome

Correlate a previously authorized `EcrAsset` with bounded, pre-discovered
ECS and EKS workload snapshots using **exact image digest URIs** and matching
AWS account and region. The result provides configuration references that can
later inform finding-level context, without inventing public exposure.

## Included

- Pure `correlate_ecr_workloads(asset, snapshots)` helper over the existing
  AWS ECR, ECS and EKS discovery data shapes
- Exact immutable image URI, AWS account ID and region matching; deterministic
  deduplicatable workload identifiers and snapshot generation timestamps
- Rejection of malformed, unsupported and oversized snapshots
- Tests for matching, cross-account/region/digest non-matching and unknown data

## Excluded and deferred

- No API endpoints, database migrations, report schema changes or deployment UI
- No inference about public ingress, executed/running containers, effective IAM
  privilege, exploitability, tenant ownership or asset criticality
- No network discovery, credential use, AWS calls or paid services
- Tenant-scoped inventory authorization **must be enforced by the caller** before
  passing these inputs. This pure module is not an authorization boundary;
  do not expose it directly to a user-supplied inventory/API payload.
- Timestamp is preserved, not interpreted as fresh or real-time. A future
  adapter must impose freshness policy before using associations in risk scores.

## Acceptance and security

All match decisions require the same immutable URI, account and region.
A missing snapshot yields no *known* configured workloads; it does not prove
there are no deployed workloads. Malformed data fails closed and is not converted
into a negative conclusion. No cross-tenant lookup, asset mutation, or new
persistence occurs. The test suite exercises those conditions; full CI and
CodeQL must pass before merge.

## Operations and cost

Function execution is offline and bounded to 500 workloads per supplied
source snapshot. Source discovery retains its existing allow-lists. No new
service, dependency, environment variable, or recurring cost (additional $0).

## Next increment

Provide an authorization-checked adapter that binds a tenant-owned scan
finding to a validated ECR asset and trusted discovery provenance, then present
the resulting configured-workload evidence as context without adjusting
priorities from unverified reachability.

## Increment 2 — Explicit authorized ECR report binding

The offline `bind_ecr_report_context(report, asset, snapshots)` helper
attaches the exact-image workload correlation to an already-authorized
container-image scan report. It validates the report target against the
immutable ECR image URI before producing output. Findings use an
`asset_context_ref` pointing to one top-level `asset_context` evidence
object; the supplied report remains unchanged. An annotated report has schema
version `1.4`, while existing `build_report` output and all API contracts
remain unchanged unless a trusted caller explicitly invokes this adapter.

**Authorization requirement:** This helper does not check database tenants.
The eventual service integration must authorize the scan job and all referenced
inventory snapshots for the same tenant before passing them to this function;
there is deliberately no public route or automatic inventory discovery in
this increment. A matching digest does not establish tenant ownership.
A failed target check, malformed snapshot or existing context fails closed.

Workload associations identify *configured* immutable image references only.
They do not prove runtime execution, internet reachability, current deployment,
or exploitability. Timestamps are preserved and must be checked for freshness
by a future adapter. No persistence, cloud permissions, dependencies, or cost
changes (additional recurring cost: $0). Regression tests cover exact-target
binding, mismatches, invalid snapshots, unknown evidence and immutability.
