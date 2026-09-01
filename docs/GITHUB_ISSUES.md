# GitHub Issue Export

The GitHub Issues integration converts one completed `secscan.json` report into one bounded Markdown issue. Preparation is offline by default. Nothing is sent to GitHub unless the operator adds `--submit`.

## Offline preparation

Use a completed report from any supported scanner:

```bash
secscan export github-issue ./reports/secscan.json \
  --repository OWNER/REPOSITORY \
  --output ./reports/github-issue.json
```

Review the generated `request.title` and `request.body`. The document has `submission: null`, and the command prints that no network request was made. At most 50 findings appear in deterministic severity/identity order; any omitted count remains explicit.

## Optional live submission

Create a fine-grained GitHub token scoped only to the destination repository with **Issues: Read and write** permission. Do not place it in the command line, `.env`, report, or repository.

Submission creates a real issue and triggers normal repository notifications. Test only in a repository where you are authorized to create issues:

```bash
export SECSCAN_GITHUB_ISSUES_TOKEN='YOUR_FINE_GRAINED_TOKEN'
secscan export github-issue ./reports/secscan.json \
  --repository OWNER/TEST-REPOSITORY \
  --output ./reports/github-issue-submission.json \
  --submit
unset SECSCAN_GITHUB_ISSUES_TOKEN
```

Open the returned URL, compare the rendered issue with the reviewed local payload, then close the test issue manually if it is no longer needed. The receipt contains the issue number and public GitHub URL, not the token.

## Automated and failure-path tests

```bash
pytest tests/test_github_issues.py
bash scripts/preflight.sh
```

The tests use fake HTTP responses. They make no GitHub request and require no token. Coverage includes deterministic truncation, invalid destinations, unsupported reports, fixed-origin request construction, required headers, token-free dry runs, missing-token rejection, HTTP failure handling, and secret non-disclosure.

## Boundaries and troubleshooting

- Only `github.com` through `https://api.github.com` is supported in this increment.
- The command creates exactly one issue per submitted invocation and does not search for duplicates. Review before each submission.
- HTTP `403` can indicate missing repository permission or rate limiting; HTTP `410` can indicate that issues are disabled. The command does not retry content creation automatically.
- GitHub applies API and content-creation rate limits. Stop and follow GitHub's response guidance when limited.
- Issue content may expose vulnerability and asset details. Use a private destination when the report is sensitive.
- Jira, Slack, ServiceNow, SIEM, web/API submission, queues, retries, labels, assignments, and GitHub Enterprise are deferred.
