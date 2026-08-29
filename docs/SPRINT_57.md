# Sprint 57 — AWS Compute Asset Association

## Goal

Add bounded read-only EC2 compute discovery and deterministic association evidence so operators can relate existing secscan targets to AWS instance identity without enabling paid AWS scanning services or mutating cloud resources.

## Scope

- Reuse the existing explicit AWS account, region, optional profile, and optional cross-account role model.
- Add an explicit `instances` allow-list per account. EC2 discovery is disabled for an account unless instance IDs are configured.
- Query only configured instance IDs with `DescribeInstances`; do not enumerate an account or region.
- Record instance ID, state, platform details, private/public IPv4 addresses, private/public DNS names, VPC/subnet, tags, and launch time as read-only inventory evidence.
- Produce deterministic schema-versioned JSON from `secscan discover ec2`.
- Derive exact candidate secscan targets only from literal discovered IP addresses; DNS names are inventory metadata, not implicit scan authorization.
- Do not launch scans automatically. The inventory is association evidence for later asset correlation.

## Security and correctness boundaries

- AWS access is read-only and uses the existing credential chain or explicitly configured short-lived assumed-role credentials.
- Account and region are explicit allow-lists and instance IDs are explicit allow-lists.
- No wildcard or implicit all-instance discovery is supported.
- No SSM, Inspector, snapshots, AMI export, instance mutation, tagging, start/stop/reboot, security-group mutation, or credential persistence is added.
- Public/private DNS names are never converted into scan targets by this sprint.
- AWS credentials and session tokens are never written to inventory or logs.

## Cost

Current recurring secscan infrastructure/service cost remains **$0**. EC2 `DescribeInstances` is a read-only control-plane API; this sprint does not create AWS resources or enable paid scanning services. Existing customer AWS resources remain outside secscan's cost model.

## Acceptance criteria

- AWS config accepts validated, unique EC2 instance IDs per account while preserving existing ECR behavior.
- `secscan discover ec2 --config ... --output ...` returns only explicitly approved instance IDs in explicitly approved regions/accounts.
- Discovery is paginated/batched through the AWS SDK without account-wide enumeration.
- Output ordering is deterministic and schema-versioned.
- Literal private/public IP addresses are emitted as candidate secscan target identities; DNS names remain metadata only.
- Same-account caller identity and explicit cross-account role boundaries are enforced through the existing AWS credential path.
- Tests cover config validation, exact instance filtering, deterministic output, same-account rejection, and cross-account short-lived credentials.
- Python 3.12/3.14 quality/package checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before merge.
