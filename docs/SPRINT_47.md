# Sprint 47 — Auth and Extension Route Ordering Fix

## Goal

Restore the browser authentication and SSH host-trust routes in the composed secscan service by ensuring explicit FastAPI routes are registered before the web UI's root `StaticFiles` catch-all.

## Problem

The service startup path mounted the web UI before authentication and SSH host-trust extensions. `mount_web_ui()` ends by mounting static assets at `/`. Starlette evaluates routes in registration order, so the root static mount intercepted later `/login`, `/register`, authentication API, and SSH host-trust routes. The authentication middleware still redirected unauthenticated browser requests to `/login`, producing a reproducible `303 -> /login -> 404` failure while `/healthz` remained healthy.

## Stories

1. As a browser user, an unauthenticated request to `/` redirects to a working `/login` page rather than a 404.
2. As an operator, authentication and SSH host-trust extension routes remain reachable and protected even though the browser UI owns the root static mount.
3. As a maintainer, the real `secscan-service` assembly path has regression coverage so route-ordering failures are caught before merge.

## Acceptance criteria

- `mount_auth()` is invoked before the root static web mount
- `mount_ssh_host_trust()` is invoked before the root static web mount
- `mount_web_ui()` remains last because it installs `StaticFiles` at `/`
- unauthenticated `GET /` returns a redirect to `/login`
- `GET /login` returns HTTP 200 through the fully assembled service app
- existing API/session/bearer-token behavior is otherwise unchanged
- CI container smoke verifies the login route, not only `/healthz`
- Python 3.12/3.14 preflight, container/Compose smoke, authenticated Linux fixture, Trivy self-scan, CodeQL workflow, and the separate GitHub code-scanning check are green before merge

## Security boundaries

This sprint does not weaken authentication, make protected routes public, change session-cookie security, alter bearer-token validation, change SSH trust semantics, enable TOFU, or add new remote access. The fix changes route registration order only so the intended authentication boundary can actually reach its explicit routes.

## Cost

- current recurring secscan infrastructure/service cost: **$0**
- projected recurring cost introduced by this sprint: **$0**
- no AWS resources or paid SaaS integrations are activated

## Demonstration

Run the normal Compose service and confirm:

1. `/healthz` returns 200.
2. unauthenticated `/` returns 303 to `/login`.
3. `/login` returns 200 and renders the sign-in page.
4. protected `/api/v1/jobs` returns 401 until a valid browser session or bearer token is supplied.
