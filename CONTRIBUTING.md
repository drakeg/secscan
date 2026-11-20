# Contributing to secscan

Secscan welcomes small, reviewable security and usability improvements. See [repository-wide standards](https://github.com/drakeg/madmallard-repository-standards/blob/main/CONTRIBUTING.md), with this project's security requirements taking precedence.

## Workflow

1. Triage bugs, feature proposals, and dependency changes into `BACKLOG.md` and the current `SPRINTS.md` sprint. Urgent correctness/security issues take priority.
2. Work on a short-lived feature branch; make one independently reviewable change per PR where practical.
3. Include a user problem, acceptance criteria, security and tenant boundaries, migration/rollback impact, cost impact, and related issue/sprint in the PR.
4. Add regression tests before or with a fix. Run `bash scripts/preflight.sh` (Ruff, mypy, pytest, wheel integrity), `python scripts/check_readme_badges.py`, and `docker compose config --quiet`. Docker build/smoke runs in GitHub CI.
5. Fix failed checks before requesting merge. Respect branch protections and required reviewer approval; don't assume a passed build is a deployed application.
6. Update `README.md`, `SPRINTS.md`, `BACKLOG.md`, `AGENTS.md`, and affected `docs/` records in the same PR.

## Definition of done

Acceptance tests and CI pass; the change is safe for the existing tenant authorization model; new endpoints have bounded input and explicit authorization; documentation and verified badges are current; no unexpected paid dependencies are introduced; release impact is described.

Never scan a target without authorization, include secrets in bug reports, or label unverified cloud inventory as confirmed exposure.
