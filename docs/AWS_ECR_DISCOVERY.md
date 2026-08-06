# AWS ECR Discovery and Authenticated Scanning

Sprint 11 adds read-only inventory of explicitly approved Amazon ECR repositories. Sprint 12 adds an explicit authenticated scan of one inventoried digest through the existing image pipeline. Neither command enumerates repositories, mutates AWS resources, or creates recurring infrastructure.

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

## Scan one inventoried image

Select the exact immutable `image_uri` from `ecr-assets.json` and provide the same AWS allow-list configuration:

```bash
secscan scan ecr \
  '123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@sha256:FULL_DIGEST' \
  --inventory ./reports/ecr-assets.json \
  --aws-config ./aws-discovery.yaml \
  --output-dir ./reports/ecr-scan \
  --fail-on HIGH
```

secscan verifies that the URI appears exactly once in the versioned inventory and that its account, region, and repository remain approved by the YAML configuration. The scan then reuses the standard image pipeline, including normalized JSON, HTML, CycloneDX, policy, baseline, history, timeout, and exit-code behavior.

Only one digest can be scanned per command. Tags are not accepted as selectors because they are mutable.

## Scan a bounded batch

Repeat `--image-uri` for each exact immutable URI. A batch accepts between 1 and 20 unique inventory URIs and runs sequentially:

```bash
secscan batch ecr \
  --image-uri '123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/api@sha256:FIRST_FULL_DIGEST' \
  --image-uri '123456789012.dkr.ecr.us-east-1.amazonaws.com/platform/worker@sha256:SECOND_FULL_DIGEST' \
  --inventory ./reports/ecr-assets.json \
  --aws-config ./aws-discovery.yaml \
  --output-root ./reports/ecr-batch \
  --fail-on HIGH
```

The output root must be empty. Each image receives an index-and-digest subdirectory such as `01-a1b2c3d4e5f6/`. All scans share `<output-root>/secscan.db` by default, and `<output-root>/batch.json` records per-image and aggregate results.

The aggregate exit code is:

- `0` when every scan completes and passes policy
- `1` when any scan has an operational failure
- `2` when no operational failure occurs and at least one scan fails policy

The complete selection is validated before the first scan. Batch execution does not add concurrency, retries, resume behavior, scheduling, or implicit inventory selection.

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

Authenticated scans additionally need an ECR authorization token and read access to the selected repository layers:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetEcrAuthorizationToken",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "PullApprovedEcrImage",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:us-east-1:123456789012:repository/platform/api"
    }
  ]
}
```

For cross-account scans, attach these permissions to the configured target role. The source identity needs only permission to assume that exact role.

This increment targets the standard commercial AWS partition (`arn:aws` and `amazonaws.com`). AWS GovCloud and China partition handling remains out of scope.

## Local testing procedures

### Automated tests without AWS credentials

Use Python 3.12 or newer from the repository root:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest tests/test_aws.py tests/test_cli_ecr.py tests/test_trivy.py -v
```

These tests use local fakes. They verify configuration validation, explicit repository scoping, pagination, normalized inventory output, exact digest selection, batch bounds and duplicate rejection, allow-list revalidation, short-lived credential mapping, CLI parsing, isolated batch outputs, aggregate manifests, and child-process environment isolation. They do not contact AWS or incur charges.

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

7. Add the pull permissions above, select one non-production digest from the inventory, and run:

   ```bash
   secscan scan ecr \
     'COPY_EXACT_IMAGE_URI_FROM_INVENTORY' \
     --inventory ./reports/ecr-assets.json \
     --aws-config ./aws-discovery.yaml \
     --output-dir ./reports/ecr-smoke-test \
     --fail-on CRITICAL
   ```

8. Confirm the command writes `trivy.json`, `secscan.json`, `secscan.html`, `secscan.cdx.json`, and `secscan.db`. Search those files for credential variable names; none should be present:

   ```bash
   if grep -R -E 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN' \
     ./reports/ecr-smoke-test; then
     echo 'unexpected credential material found in scan artifacts' >&2
     false
   fi
   ```

9. To smoke-test batching, choose two non-production immutable URIs, use a new empty output root, and run the bounded batch example above. Confirm `batch.json` contains two entries, each output directory contains the standard artifacts, and `secscan.db` contains both scan history records.

The discovery and scan commands do not create AWS resources. Image-layer downloads can incur AWS data-transfer or surrounding registry costs, and Trivy may download vulnerability databases. This feature has no required recurring secscan-managed infrastructure.

## Failure behavior and boundaries

- A same-account entry without `role_arn` must match `sts:GetCallerIdentity`.
- A cross-account entry requires an exact role ARN for that account.
- Invalid accounts, regions, repository names, duplicates, permission errors, and AWS API errors stop the command with exit code `1`.
- Credentials and session tokens are never written to the inventory.
- Scan credentials are supplied only to the Trivy child process and are not included in its command arguments.
- Batch scans require 1–20 explicit unique digest URIs and run sequentially.
- Tags, wildcards, repository-wide selection, concurrency, retries, resume, automatic scheduling, service-mode ECR scans, and resource mutation remain out of scope.
