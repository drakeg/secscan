# Sprint 70 — Tenant-Owned Projects and Project Authorization

## Goal

Introduce a small, durable project boundary inside each tenant so scans and future integrations can be grouped without weakening the tenant-isolation model established in Sprints 58–69.

## Scope

This sprint will:

- add tenant-owned project records with stable IDs, names, creation metadata, and an enabled state
- allow authenticated tenant members to list projects in their active tenant
- allow tenant owners to create, rename, and disable projects
- prevent project lookup or mutation across tenant boundaries
- add an optional project association to scan jobs while preserving compatibility for existing jobs
- validate that a submitted project belongs to the request's active tenant before a job is persisted or executed
- expose project metadata in authenticated job/API responses where applicable
- add focused API and persistence regression tests for project authorization and job association
- keep existing tenant membership, invitation, scanner, Docker, and CLI behavior green

## Authorization model

- Tenant membership remains the outer authorization boundary.
- A project belongs to exactly one tenant.
- Any active tenant member may list and use enabled projects belonging to that tenant for scans.
- Only a tenant owner may create, rename, or disable projects in that tenant.
- No global secscan `admin` role bypasses tenant/project ownership checks.
- Disabled projects remain addressable for historical job evidence but cannot receive new scans.
- Project IDs supplied by clients are never trusted without a tenant-scoped database lookup.

## Compatibility

Existing jobs without a project remain valid. Project association is optional in Sprint 70 so this migration does not silently assign historical evidence to a project or break current scanner submission paths.

## Explicitly deferred

- project-specific member roles or ACLs beyond tenant membership
- moving projects between tenants
- project deletion that could orphan historical evidence
- per-project API keys, quotas, billing, or policy overrides
- project-scoped cloud/SSH credential sharing
- project hierarchy, folders, or tags

## Security boundaries

- Every project read/write is tenant scoped.
- A project ID from another tenant fails closed and must not disclose cross-tenant metadata.
- Disabled projects cannot be selected for new jobs.
- Existing tenant isolation for jobs, credentials, host trust, invitations, billing, and cloud assets is unchanged.
- No secrets or credentials are added to project records.

## Cost

Current and projected recurring secscan service cost remains **$0**. This sprint uses the existing SQLite/application boundary and activates no paid service.

## Acceptance criteria

- owners can create, rename, and disable projects in their active tenant
- members can list and use enabled projects but cannot administer them
- cross-tenant project reads, mutations, and job associations fail closed
- new jobs can optionally persist a validated project association
- disabled projects reject new scan association while historical job records remain readable
- jobs without a project remain supported
- Python 3.12/3.14 quality/tests, wheel/package validation, Docker/Compose smoke, Trivy self-scan, and CodeQL are green before merge
