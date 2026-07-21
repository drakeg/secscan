# Agile Delivery Model

## Approach

`secscan` will be developed in short, demonstrable increments. Each sprint should produce a usable improvement rather than only internal plumbing.

The initial planning assumption is a two-week sprint cadence, but scope completion—not calendar pressure—determines whether work is accepted. Sprint plans can be adjusted during backlog refinement without changing the product vision.

## Roles

For the current small-team phase:

- **Product Owner:** defines priorities, accepts completed work, and resolves product tradeoffs.
- **Developer/Engineering:** designs, implements, tests, documents, and demonstrates increments.
- **Security reviewer:** initially performed as part of engineering review; may become a separate role later.

## Ceremonies

### Sprint planning

At the start of each sprint:

1. Confirm the sprint goal.
2. Select only stories that support that goal.
3. Define acceptance criteria and dependencies.
4. Identify security, cost, and operational risks.

### Daily progress

Progress is tracked through focused GitHub issues and pull requests. Blockers should be recorded immediately rather than deferred until the end of the sprint.

### Backlog refinement

Refinement occurs before the next sprint. Stories are split when they cannot be demonstrated independently or cannot reasonably fit within one sprint.

### Sprint review

Every sprint ends with a working demonstration against known targets. Documentation-only completion does not substitute for a working increment unless documentation is the sprint's explicit goal.

### Retrospective

Record:

- what worked
- what caused rework
- what should change in the next sprint
- whether architecture or scope assumptions remain valid

## Work-item hierarchy

- **Epic:** a major product capability spanning multiple sprints.
- **Story:** a user-visible or operator-visible outcome.
- **Task:** implementation work needed to complete a story.
- **Spike:** time-boxed research intended to reduce uncertainty.

## Prioritization

Backlog ordering uses this sequence:

1. Security and correctness risks
2. Capabilities required for a useful end-to-end scan
3. Automation and operator experience
4. Scale, integrations, and advanced intelligence

## Source-control workflow

- `main` should remain releasable.
- Each story or tightly related story group uses a focused branch.
- Pull requests document scope, validation, and expected impact.
- Unrelated changes are not bundled into the same pull request.
- Releases are tagged using semantic versioning once the first distributable version exists.

## Definition of ready

A story is ready when:

- its user or operator outcome is clear
- acceptance criteria are testable
- dependencies are known
- major security implications are identified
- it is small enough to complete within one sprint

## Sprint reporting

Each sprint should report:

- committed stories
- completed stories
- carryover and reason
- demonstration result
- discovered risks or decisions
- projected infrastructure and service costs, including current and likely future monthly costs when cloud services are introduced
