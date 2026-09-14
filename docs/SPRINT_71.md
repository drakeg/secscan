# Sprint 71 — Project-Specific Member Access Control

## Goal

Build the next authorization layer on the tenant-owned project boundary from Sprint 70 so a tenant can restrict individual projects to explicitly authorized members without weakening tenant isolation or historical evidence.

## Scope

This sprint will:

- add durable project membership records scoped to one tenant-owned project and one tenant member
- define project roles `viewer` and `operator`, with tenant owners retaining administrative authority
- allow tenant owners to grant, change, and revoke project access for members of the same tenant
- allow authorized project members to discover only projects they may access
- require `operator` access (or tenant owner) before a new scan can be associated with a restricted project
- allow `viewer` access to read project metadata and historical project-associated job evidence
- preserve current behavior for projects that have no explicit project memberships during the migration
- prevent cross-tenant users and non-members from learning project membership metadata
- add focused persistence/API/job-authorization regression tests

## Authorization model

- Tenant membership remains the outer boundary: project access can never grant access outside the user's active tenant.
- Tenant owners may administer every project in their active tenant.
- A project `operator` may submit scans to that project and read its project/job evidence.
- A project `viewer` may read project/job evidence but may not submit scans to that project.
- Project members may not grant, change, or revoke project access.
- Users without project access receive non-disclosing not-found behavior for restricted project reads.
- A project with zero explicit project memberships remains tenant-member accessible for compatibility; once explicit membership is configured, access becomes restricted to project members plus tenant owners.
- Disabled projects retain historical read behavior but reject new scan associations regardless of project role.

## Compatibility

Sprint 70 projects remain usable immediately after migration. No existing project becomes inaccessible merely because the ACL table exists. Restriction begins only when an owner explicitly grants project membership, avoiding a silent authorization change for existing installations.

## Explicitly deferred

- custom project roles or per-action permission matrices
- project ownership transfer or deletion
- nested groups/teams and inherited project permissions
- per-project API keys, quotas, billing, policy overrides, or secrets
- project-scoped cloud/SSH credential sharing
- external identity/OIDC group synchronization

## Security boundaries

- Every ACL lookup is constrained by both active tenant and project identity.
- Grant targets must already be members of the same tenant.
- Cross-tenant user IDs and project IDs fail closed without disclosing metadata.
- Tenant/global application roles do not bypass project ACLs except the explicit active-tenant owner rule.
- ACL changes do not mutate or orphan historical job evidence.
- Existing tenant/session protections remain unchanged.

## Cost

Current and projected recurring secscan service cost remains **$0**. The sprint uses the existing SQLite/application authorization boundary and activates no paid service.

## Acceptance criteria

- tenant owners can grant, change, list, and revoke project viewer/operator access for same-tenant members
- non-owners cannot administer project ACLs
- operators can submit project scans; viewers cannot
- authorized viewers/operators can read permitted project metadata and historical project jobs
- unauthorized and cross-tenant project access fails closed without metadata disclosure
- projects with no explicit ACL entries retain Sprint 70 tenant-member behavior
- disabled projects reject new scans while permitted historical reads remain available
- unprojected jobs remain unaffected
- Python 3.12/3.14 quality/tests, wheel/package validation, Docker/Compose smoke, Trivy self-scan, and CodeQL are green before merge
