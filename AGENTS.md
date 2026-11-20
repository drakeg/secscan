# Secscan — Agent and Maintainer Instructions

Scope: **drakeg/secscan only**. Follow the guidance in [Mad Mallard Repository Standards](https://github.com/drakeg/madmallard-repository-standards/blob/main/AGENTS.md) where compatible; this repository's security restrictions, architecture and `docs/ENGINEERING_STANDARDS.md` take precedence.

## Execution discipline

- Build → test → fix → repeat; use the existing Docker Compose test stack and CI. Report actual results, not assumed passes or deployments.
- Work on small, reviewable branches and PRs. Do not bypass branch protections, deploy paid services, or merge without required checks and review.
- Continue the next ready backlog task after a completed sprint/PR. Prioritize broken CI, security regressions, and working SMB demos.
- Read `README.md`, `SPRINTS.md`, `BACKLOG.md`, `CONTRIBUTING.md`, `RELEASES.md`, `SECURITY.md` (if present), and `docs/ENGINEERING_STANDARDS.md` before modifying relevant behavior.
- Maintain all root planning documents and the detailed `docs/SPRINT_N.md` records in the same PR as code changes.
- Preserve tenant isolation, fail-closed input validation, approved scanner targets and independent AWS discovery provenance. Never promote operator-submitted AWS inventory to verified evidence.
- Run `bash scripts/preflight.sh` and `docker compose config --quiet` when available. CI must validate Python 3.12/3.14, container smoke and CodeQL before merge.
- Never commit secrets, real customer data, credentials, private scanning results, or license claims unsupported by repository evidence.

## README badge maintenance

The bounded badge block directly beneath the root H1 must reflect actual `pyproject.toml`, Python modules, `Dockerfile`, `compose.yaml`, `.github/workflows`, and release/license status. Keep 2–3 compact rows. Use dynamic workflow, issue and PR badges; no hardcoded CI success. Technology version claims must be verified. Run `python scripts/check_readme_badges.py` as part of preflight/CI and update its expectations when stack/workflow changes.

No LICENSE file or published release was verified at the initial adoption; do **not** add a license or release-version badge before it exists. Adding a license requires maintainer approval.

## Business and release discipline

Target SMB operators and small agencies who need repeatable vulnerability evidence and actionable remediation reports, not a full enterprise CSPM replacement. Prefer demo-able workflows and verified customer demand over speculative architecture. Pricing and demand remain hypotheses until tested.

Follow `RELEASES.md` and the existing guarded release workflow. PR merges are not automatic releases. Include tests, migration/rollback notes, cost impact, and PR links in each update.
