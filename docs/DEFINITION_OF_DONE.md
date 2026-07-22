# Definition of Done

A story is done only when all applicable criteria below are satisfied.

## Functionality

- acceptance criteria are met
- behavior is demonstrated against an agreed target
- failure paths are handled explicitly
- no unrelated functionality is changed

## Code quality

- implementation follows documented component boundaries
- public interfaces and non-obvious decisions are documented
- configuration is externalized where appropriate
- scanner-specific behavior remains isolated in its scanner plugin and engine adapter
- scanner plugins do not import CLI parsing or report-writing concerns
- scanners return normalized project-owned models
- temporary debugging code and unused dependencies are removed

## Testing

- unit tests cover new normalization, policy, registry, and error-handling logic
- integration or smoke tests cover the user-visible path
- tests include at least one expected success and one expected failure
- scanner plugins have contract and registration coverage
- test fixtures do not contain live credentials or confidential data
- Ruff, mypy, pytest, wheel verification, clean installation, container smoke tests, Trivy self-scan, and CodeQL pass before merge

## Security

- dependencies and container image are scanned when tooling exists
- secrets are not committed, logged, or written to artifacts
- inputs, paths, subprocess arguments, and output locations are validated
- privileged access is avoided or explicitly documented and justified
- new external dependencies have a compatible license and pinned version
- plugin registration rejects ambiguous or duplicate scanner names

## Documentation

- README or task-specific documentation reflects user-visible changes
- commands can be copied and run as documented
- exit codes, artifact formats, and configuration changes are documented
- architecture or ADR documentation is updated for material decisions
- scanner capabilities, boundaries, and deferred behavior are explicit
- known limitations are explicit

## Operations and cost

- resource requirements are documented when materially changed
- current recurring cost is documented
- likely future monthly costs are estimated before enabling paid cloud services
- logs and errors provide enough context to diagnose failures without exposing secrets

## Delivery

- work is committed on a focused branch
- pull request explains what changed, why, and how it was validated
- review feedback is resolved or explicitly deferred
- all required GitHub checks pass before merge
- merged code leaves `main` in a releasable state

## Sprint acceptance

A sprint is complete when:

- its goal is demonstrably achieved
- accepted stories meet this Definition of Done
- incomplete stories return to the backlog with a stated reason
- documentation and cost outlook are current
- the next highest-priority risks are recorded
