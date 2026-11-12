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
