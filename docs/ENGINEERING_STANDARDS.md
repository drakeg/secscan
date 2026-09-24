# Engineering Standards

These standards apply to all secscan development. Sprint-specific documents define scope; this document defines how implementation work is performed and accepted.

## Core principles

1. Keep `main` releasable.
2. Prefer small, focused, independently reviewable pull requests.
3. Security and correctness take precedence over feature velocity.
4. Reuse existing authorization, validation, persistence, and execution boundaries instead of creating parallel paths.
5. Fail closed at trust boundaries. Missing, stale, cross-tenant, malformed, or unauthorized data must not silently broaden access.
6. Preserve backward compatibility unless a deliberate breaking change is documented.
7. Do not introduce paid services, recurring infrastructure, or external dependencies without explicit product approval and documented cost impact.
8. Documentation and tests are part of the implementation, not follow-up work.

## Sprint documentation

Every committed sprint must have a `docs/SPRINT_<N>.md` record or an equivalent clearly linked section containing:

- sprint goal and operator/user outcome
- included and explicitly excluded scope
- acceptance criteria
- security and authorization boundaries
- persistence/migration implications
- testing and validation strategy
- operational and restart/failure behavior where applicable
- current and projected recurring cost impact
- important design decisions and deferred work

Incremental PRs within a sprint should update the sprint document as behavior changes. At sprint completion, the roadmap must accurately reflect delivered behavior and remaining backlog.

## Coding standards

### Python

- Support the Python versions enforced by CI.
- Add type annotations to new public functions, methods, and non-obvious internal boundaries.
- Keep mypy and Ruff clean; do not weaken checks merely to make CI pass.
- Prefer explicit domain types, dataclasses, Pydantic models, and small composable services over unstructured dictionaries.
- Use `pathlib.Path` for filesystem paths.
- Use timezone-aware UTC datetimes for persisted or compared timestamps.
- Bound user-controlled collection sizes, timeouts, concurrency, polling intervals, and resource consumption.
- Avoid mutable default arguments and hidden global state.
- Catch only exceptions that can be handled meaningfully; do not broadly suppress unexpected failures.
- Never log credentials, tokens, private keys, authorization headers, or secret-bearing URLs.

### Persistence

- SQLite schema changes must be restart-safe and compatible with existing databases.
- Migrations must be idempotent.
- Tenant-owned records must include tenant scoping in reads and mutations.
- Database uniqueness and authorization assumptions must be enforced by schema or transactional code, not only application checks.
- Concurrency-sensitive state transitions must be atomic and have regression tests.
- Never silently delete or rewrite user data to resolve a migration ambiguity.

### API and web

- Authenticate before accessing tenant-owned resources.
- Re-evaluate current authorization on sensitive mutations; do not rely solely on the creator's historical permissions.
- Use consistent HTTP status semantics and avoid leaking cross-tenant resource existence.
- Validate input before persistence or execution.
- Keep secrets out of API responses and public metadata.
- Mount order and middleware behavior are part of the security model and require tests when changed.

### Scanner and command execution

- Scanner targets and flags must pass existing validation boundaries.
- Do not construct shell command strings from user input. Use argument arrays and controlled environments.
- Network, DAST, cloud, and credentialed scanning must retain explicit authorization/scope controls.
- Filesystem inputs must remain within configured allowed roots.
- Remote repository URLs must be validated and credential-free.
- Temporary credentials belong only in the minimum required child-process environment and must not be persisted.

## Testing standards

Every behavioral change requires tests at the narrowest useful level. Add regression coverage for every fixed defect.

Before merge, the branch must pass the repository preflight and required GitHub checks, including:

- Ruff/linting
- mypy/static typing
- pytest
- package/build integrity
- supported Python versions
- Docker image and Docker Compose validation where applicable
- security scanning/CodeQL

Tests must be deterministic and credential-free by default. External/cloud integration tests must be opt-in, narrowly scoped, and documented. Tests must not depend on execution order, production paths, or writable system directories.

When a new service component is mounted or wired, update service composition tests so isolation remains intact.

## Pull-request standards

Each PR should state:

- what changed and why
- sprint/story or issue relationship
- security or authorization impact
- persistence/migration impact
- validation performed
- intentionally deferred work
- cost impact when relevant

Do not mix unrelated cleanup with feature work. Keep draft PRs draft until required checks are green and the increment is internally complete. A failed pipeline is a development failure to diagnose and fix, not a check to bypass.

## Documentation standards

Update user/operator documentation in the same PR whenever commands, configuration, environment variables, permissions, API behavior, Docker Compose usage, or security boundaries change.

Examples must be safe to copy. Use placeholders for secrets and authorized targets. Document defaults, limits, failure modes, and cleanup steps. Keep `.env.example` synchronized with supported environment variables and never commit populated secret files.

## Definition of done

Work is done only when:

- acceptance criteria are implemented
- relevant tests and regression tests exist
- documentation reflects actual behavior
- security/tenant boundaries have been reviewed
- migrations and restart behavior are considered
- local/container workflows remain usable
- required CI and CodeQL checks pass
- no unauthorized recurring cost or external dependency was introduced
- deferred work is recorded rather than implied complete


## Pre-PR validation gate

Before opening or updating a pull request, contributors and automation should run the repository preflight locally whenever the environment permits:

```bash
python -m pip install -e '.[dev]'
bash scripts/preflight.sh --quick
```

The quick gate runs Ruff, mypy, and the complete pytest suite—the same first-line Python checks used by CI—without rebuilding/reinstalling the wheel. Before merge/release, `bash scripts/preflight.sh` remains the full package-integrity gate, and `bash scripts/preflight.sh --container` adds the local container security check.

When repository-writing automation cannot execute the checkout locally, it must still inspect changed test structure and the existing preflight/CI contract before opening the PR, and CI failures must be treated as regressions in the development process rather than normal validation.
