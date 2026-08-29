# Sprint 60 — Billing Provider and Enforced Subscription Lifecycle

## Goal

Replace the no-charge Professional preview toggle with an enforceable, tenant-bound subscription lifecycle while keeping local/self-hosted Free usage independent of any payment provider.

## Provider decision

Sprint 60 uses Stripe-hosted Checkout and Stripe Billing Portal. The integration is implemented with the Stripe HTTPS API and verified webhook protocol rather than embedding payment fields or storing card data in secscan.

Stripe is entirely opt-in. With all Stripe environment variables blank:

- secscan makes no Stripe API requests
- Free registration and Free scanning remain available
- Professional selection is disabled in the registration UI
- billing endpoints report that billing is not configured

If any Stripe variable is supplied, the full required configuration must be present or service startup fails closed.

## Scope

- tenant-bound Stripe Checkout Session creation for the Professional recurring Price
- Stripe-hosted Billing Portal session creation for subscription management/cancellation
- raw-body `Stripe-Signature` HMAC verification with a five-minute replay tolerance
- idempotent persisted webhook event IDs
- persisted tenant billing state with Stripe customer/subscription identifiers and status
- Professional entitlement only for verified `active` or `trialing` subscription state
- downgrade to Free when a subscription is deleted/canceled or an invoice payment fails
- existing preview-era Professional rows are downgraded to Free unless backed by persisted active/trialing subscription state
- direct `PUT /api/v1/account/plan` escalation to Professional is rejected
- active subscriptions must be changed/canceled through the billing portal rather than by mutating the local plan cache
- registration can request Professional, but the account remains Free until the verified subscription webhook activates it
- Compose and `.env.example` expose only server-side Stripe configuration

## Required configuration

All four variables are required together:

- `SECSCAN_STRIPE_SECRET_KEY`
- `SECSCAN_STRIPE_WEBHOOK_SECRET`
- `SECSCAN_STRIPE_PROFESSIONAL_PRICE_ID`
- `SECSCAN_PUBLIC_BASE_URL`

`SECSCAN_PUBLIC_BASE_URL` must be HTTPS except for localhost/127.0.0.1 development URLs.

Configure the Stripe webhook destination as:

`<SECSCAN_PUBLIC_BASE_URL>/api/v1/billing/webhook`

Subscribe to at least:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_failed`

## Security boundaries

- Raw payment-card data is never collected, logged, or stored by secscan.
- The Stripe secret key and webhook signing secret are server-side environment values only.
- The webhook route is unauthenticated at the session layer because Stripe must call it, but every accepted request must pass signature and timestamp verification against the configured webhook secret.
- Tenant identity is set by secscan in Checkout/subscription metadata; clients cannot select another tenant ID.
- A completed Checkout Session alone does not grant Professional access. Only a verified subscription event reporting `active` or `trialing` state can grant the entitlement.
- Direct plan mutation cannot grant Professional access.
- Failed payment and canceled/deleted subscription states fail closed to Free.
- Stripe event IDs are persisted for idempotency.
- No raw Stripe secret or webhook secret is persisted in SQLite.

## Cost outlook

The secscan infrastructure/service recurring cost remains **$0/month** when Stripe is unconfigured and for normal local development/test execution.

For a production Stripe account, standard hosted Checkout does not require a fixed monthly secscan infrastructure cost, but Stripe charges transaction/Billing fees when paid subscriptions transact. As of Sprint 60 planning, Stripe publicly lists standard US domestic-card processing at 2.9% + $0.30 per successful transaction; Stripe Billing fees may apply in addition depending on the selected Billing plan. Optional Stripe Checkout/Billing Portal custom domains can add a monthly provider fee and are not required or enabled by secscan.

Provider pricing changes independently of this repository and must be re-verified before production launch or plan-price decisions.

## Acceptance criteria

- Free works with zero Stripe configuration and triggers no Stripe request.
- Partial Stripe configuration fails closed.
- Professional cannot be granted with the legacy plan PUT endpoint.
- Professional registration requests remain Free until verified subscription activation.
- Checkout is created server-side with the configured recurring Price and secscan tenant metadata.
- Valid signed active/trialing subscription events grant Professional.
- Invalid, stale, or unsigned webhook requests are rejected.
- Duplicate event IDs are idempotent.
- canceled/deleted subscriptions and payment failures remove Professional entitlement.
- Billing Portal is available only when a Stripe customer association exists.
- package verification requires the billing module.
- Compose passes only the documented server-side billing environment variables to the service.
- Ruff, mypy, pytest, wheel/clean-install validation, Docker/Compose smoke, Trivy self-scan, CodeQL workflow, and separate GitHub Advanced Security CodeQL are green before acceptance.

## Deferred

- taxes, coupons, trials configured beyond Stripe Price/account settings
- multiple paid tiers or seat-based metering
- tenant-member billing roles and billing-admin delegation
- refunds/credits/disputes UI
- invoice history UI
- per-tenant API keys/OIDC
- production secret-manager integration
