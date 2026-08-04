# AWS ECR Asset Discovery

Sprint 11 adds read-only inventory of explicitly approved Amazon ECR repositories. Discovery does not pull or scan images, enumerate repositories, mutate AWS resources, or create recurring infrastructure.

## Configuration

Account IDs must be quoted so YAML preserves all 12 digits. Every account requires explicit regions and repository names; wildcards are not supported.

```yaml
profile: secscan-readonly

accounts:
  - account_id: "123456789012"
    regions:
      - us-east-1
      - us-west-2
    repositories:
      - platform/api
      - platform/worker

  - account_id: "210987654321"
    role_arn: arn:aws:iam::210987654321:role/SecscanEcrDiscovery
    regions:
      - us-east-1
    repositories:
      - shared/base-image
```

Run discovery:

```bash
secscan discover ecr \
  --config ./aws-discovery.yaml \
  --output ./reports/ecr-assets.json
```

The JSON inventory contains account, region, repository, immutable digest URI, tags, pushed time, and compressed size for each image. Treat it as security-sensitive infrastructure inventory.

## Least-privilege IAM

For same-account discovery, the active identity needs `ecr:DescribeImages` for only the configured repositories. secscan calls `sts:GetCallerIdentity` to verify the account; AWS does not require an explicit permission for that identity call.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadApprovedEcrImages",
      "Effect": "Allow",
      "Action": "ecr:DescribeImages",
      "Resource": [
        "arn:aws:ecr:us-east-1:123456789012:repository/platform/api",
        "arn:aws:ecr:us-east-1:123456789012:repository/platform/worker"
      ]
    }
  ]
}
```

For cross-account discovery, the source identity also needs `sts:AssumeRole` for the exact configured role. The target role trust policy must trust that source identity, and the target role needs the repository-scoped `ecr:DescribeImages` permission above. secscan uses a short-lived session named `secscan-ecr-discovery`.

This increment targets the standard commercial AWS partition (`arn:aws` and `amazonaws.com`). AWS GovCloud and China partition handling remains out of scope.

## Local testing procedures

### Automated tests without AWS credentials

Use Python 3.12 or newer from the repository root:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest tests/test_aws.py -v
```

These tests use local fakes. They verify configuration validation, explicit repository scoping, pagination, normalized inventory output, and cross-account identity rejection. They do not contact AWS or incur charges.

Run the complete repository validation before submitting changes:

```bash
PATH="$PWD/.venv/bin:$PATH" bash scripts/preflight.sh
```

### Optional live AWS smoke test

1. Create a read-only IAM identity or role using the policy above.
2. Configure credentials through the standard AWS credential chain or the named `profile` in the YAML file.
3. Start with one non-production repository in one region.
4. Confirm the active identity before discovery:

   ```bash
   aws sts get-caller-identity --profile secscan-readonly
   ```

5. Run `secscan discover ecr` and inspect the output:

   ```bash
   secscan discover ecr --config ./aws-discovery.yaml --output ./reports/ecr-assets.json
   python -m json.tool ./reports/ecr-assets.json >/dev/null
   ```

6. Confirm `asset_count` and the account, region, repository, and digest values match the approved repository.

The discovery calls do not create AWS resources. Normal AWS data-transfer or surrounding account costs remain possible, but this feature has no required recurring infrastructure and ECR inventory API usage has no secscan-managed cost.

## Failure behavior and boundaries

- A same-account entry without `role_arn` must match `sts:GetCallerIdentity`.
- A cross-account entry requires an exact role ARN for that account.
- Invalid accounts, regions, repository names, duplicates, permission errors, and AWS API errors stop the command with exit code `1`.
- Credentials and session tokens are never written to the inventory.
- Repository enumeration, image pulls, ECR authentication, automatic scans, scheduling, and resource mutation remain out of scope.
