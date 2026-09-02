# Sprint 57 — AWS Compute Asset Association

## Goal

Add bounded, read-only EC2 inventory and associate approved instances with existing secscan assessment assets without starting scans or mutating AWS resources.

## Operator outcome

An operator can run `secscan-ec2` with an explicit YAML allow-list of AWS account, region, and exact EC2 instance IDs. The command writes a versioned EC2 inventory. When an existing secscan service `jobs.db` is supplied, discovered instances are associated with existing network/Linux/Windows scan assets by exact IP or DNS target equality.

## Scope

- separate `secscan-ec2` command packaged with secscan
- explicit account/region/instance-ID configuration
- maximum 50 instance IDs per configured target entry
- same-account caller verification through STS
- optional exact-role ARN for short-lived cross-account credentials
- one read-only `DescribeInstances` request per configured target entry
- fail closed if AWS does not return every approved instance
- normalized instance metadata: instance ID, state, instance type, AMI ID, platform details, private/public IP and DNS, and launch time
- optional exact association to persistent secscan service assets
- versioned JSON evidence at `/reports/ec2-assets.json` by default

## Association boundary

Association is intentionally conservative. Only persistent assets produced by `network`, `linux-host`, or `windows-host` scanners are eligible, and their stored target must exactly equal one of the EC2 instance's returned private/public IP or private/public DNS names.

The sprint does **not**:

- parse a Web DAST URL and infer its host
- expand a network-range CIDR and infer membership
- match aliases, tags, instance names, or reverse DNS
- automatically launch a scan
- alter an existing secscan asset record
- persist AWS credentials or authorization tokens

This avoids false ownership claims and leaves richer cross-source correlation for a later explicit sprint.

## AWS security boundaries

- No account-wide `DescribeInstances` enumeration is supported.
- Every EC2 instance ID is explicitly configured.
- Same-account access verifies the caller account before EC2 access.
- Cross-account access requires one explicitly configured role ARN in the target account and uses short-lived STS credentials.
- Only read-only `sts:GetCallerIdentity`, optional `sts:AssumeRole`, and `ec2:DescribeInstances` permissions are required.
- AWS credentials are used in memory only and are not written to inventory output.
- Missing configured instances fail the operation instead of silently producing a partial inventory.

## Example configuration

```yaml
profile: secscan-readonly
targets:
  - account_id: "123456789012"
    region: us-east-1
    instance_ids:
      - i-0123456789abcdef0
```

Cross-account access may add:

```yaml
    role_arn: arn:aws:iam::123456789012:role/SecscanEc2Discovery
```

## Example commands

Inventory only:

```bash
secscan-ec2 --config ec2.yaml --output /reports/ec2-assets.json
```

Inventory plus exact association against the normal service database:

```bash
secscan-ec2 \
  --config ec2.yaml \
  --service-db /reports/jobs.db \
  --output /reports/ec2-assets.json
```

## Cost

Current recurring secscan infrastructure/service cost remains **$0**. AWS `DescribeInstances` and STS API calls do not require enabling a paid scanner service. Normal AWS account/network usage remains the operator's responsibility.

## Acceptance criteria

- invalid/unbounded config is rejected before discovery
- discovery sends only exact approved instance IDs to EC2
- same-account identity is verified or an explicit role is assumed
- every approved instance must be returned
- inventory is deterministic apart from `generated_at`
- exact persistent-asset associations are included only when a service DB is explicitly supplied
- unrelated scanner targets are not inferred into associations
- wheel verification includes the EC2 modules
- Python 3.12/3.14 checks, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and the separate GitHub Advanced Security CodeQL check are green before acceptance
