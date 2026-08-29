from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from secscan.auth import mount_auth
from secscan.billing import StripeBillingClient
from secscan.public_site import PlanStore, mount_public_site


def app_for(database: Path) -> FastAPI:
    app = FastAPI()

    @app.post("/api/v1/linux-host-jobs")
    def linux_host_job() -> dict[str, bool]:
        return {"accepted": True}

    mount_public_site(app, database=database)
    mount_auth(app, database=database)
    return app


def _enable_test_billing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECSCAN_STRIPE_SECRET_KEY", "sk_test_example")
    monkeypatch.setenv("SECSCAN_STRIPE_WEBHOOK_SECRET", "whsec_example")
    monkeypatch.setenv("SECSCAN_STRIPE_PROFESSIONAL_PRICE_ID", "price_professional")
    monkeypatch.setenv("SECSCAN_PUBLIC_BASE_URL", "https://secscan.example.test")


def _signed_event(event: dict[str, object]) -> tuple[bytes, str]:
    payload = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signature = hmac.new(
        b"whsec_example",
        str(timestamp).encode() + b"." + payload,
        hashlib.sha256,
    ).hexdigest()
    return payload, f"t={timestamp},v1={signature}"


def test_anonymous_visitors_can_browse_landing_login_and_registration(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))

    landing = client.get("/")
    assert landing.status_code == 200
    assert "Find what needs fixing first" in landing.text
    assert "Free" in landing.text
    assert "Professional" in landing.text
    assert "Sign in" in landing.text
    assert "Start free" in landing.text
    assert "Create an account" in landing.text
    assert "Professional billing is not configured" in landing.text

    assert client.get("/login").status_code == 200
    registration = client.get("/register")
    assert registration.status_code == 200
    assert "Choose Free" in registration.text
    assert "Choose Professional" in registration.text
    assert "billing not configured" in registration.text


def test_authenticated_landing_replaces_registration_ctas_with_workspace_actions(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))
    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201

    landing = client.get("/")
    assert landing.status_code == 200
    assert "Open workspace" in landing.text
    assert "Plan: Free" in landing.text
    assert "Create an account" not in landing.text
    assert "Start free" not in landing.text
    assert "href='/register'" not in landing.text


def test_registration_requires_plan_and_professional_requires_billing(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    client = TestClient(app_for(database))

    missing = client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.test", "password": "correct-horse-battery"},
    )
    assert missing.status_code == 422

    unavailable = client.post(
        "/api/v1/auth/register",
        json={
            "email": "paid@example.test",
            "password": "correct-horse-battery",
            "plan": "professional",
        },
    )
    assert unavailable.status_code == 503

    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201
    assert created.json()["plan"] == "free"
    user_id = created.json()["id"]
    assert PlanStore(database).get(user_id) == "free"

    account = client.get("/account/plan")
    assert account.status_code == 200
    assert "Current plan" in account.text
    assert "Free" in account.text


def test_direct_professional_toggle_is_blocked_without_verified_subscription(tmp_path: Path) -> None:
    client = TestClient(app_for(tmp_path / "jobs.db"))
    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator@example.test",
            "password": "correct-horse-battery",
            "plan": "free",
        },
    )
    assert created.status_code == 201

    blocked = client.post("/api/v1/linux-host-jobs")
    assert blocked.status_code == 403

    upgraded = client.put("/api/v1/account/plan", json={"plan": "professional"})
    assert upgraded.status_code == 409
    assert "verified subscription" in upgraded.json()["detail"]

    still_blocked = client.post("/api/v1/linux-host-jobs")
    assert still_blocked.status_code == 403


def test_verified_stripe_subscription_unlocks_and_payment_failure_relocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_test_billing(monkeypatch)
    monkeypatch.setattr(
        StripeBillingClient,
        "create_checkout_session",
        lambda self, **kwargs: {"id": "cs_test", "url": "https://checkout.stripe.test/session"},
    )
    client = TestClient(app_for(tmp_path / "jobs.db"))
    created = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator@example.test",
            "password": "correct-horse-battery",
            "plan": "professional",
        },
    )
    assert created.status_code == 201
    assert created.json()["plan"] == "free"
    assert created.json()["checkout_required"] is True
    tenant_id = created.json()["tenant_id"]

    checkout = client.post("/api/v1/billing/checkout")
    assert checkout.status_code == 200
    assert checkout.json()["url"] == "https://checkout.stripe.test/session"

    event = {
        "id": "evt_active",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_test",
                "customer": "cus_test",
                "status": "active",
                "metadata": {"secscan_tenant_id": tenant_id},
            }
        },
    }
    payload, signature = _signed_event(event)
    activated = client.post(
        "/api/v1/billing/webhook",
        content=payload,
        headers={"Stripe-Signature": signature, "Content-Type": "application/json"},
    )
    assert activated.status_code == 200
    assert client.get("/api/v1/account/plan").json()["plan"] == "professional"
    assert client.post("/api/v1/linux-host-jobs").status_code == 200

    failed_event = {
        "id": "evt_failed",
        "type": "invoice.payment_failed",
        "data": {"object": {"subscription": "sub_test"}},
    }
    payload, signature = _signed_event(failed_event)
    failed = client.post(
        "/api/v1/billing/webhook",
        content=payload,
        headers={"Stripe-Signature": signature, "Content-Type": "application/json"},
    )
    assert failed.status_code == 200
    assert client.get("/api/v1/account/plan").json()["plan"] == "free"
    assert client.post("/api/v1/linux-host-jobs").status_code == 403


def test_unsigned_billing_webhook_is_rejected_without_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_test_billing(monkeypatch)
    client = TestClient(app_for(tmp_path / "jobs.db"))

    response = client.post(
        "/api/v1/billing/webhook",
        content=b'{"id":"evt_bad","type":"test","data":{"object":{}}}',
        headers={"Stripe-Signature": "t=1,v1=bad"},
    )
    assert response.status_code == 400
    assert "signature" in response.json()["detail"].lower()


def test_existing_account_defaults_to_free_when_plan_column_is_added(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    from secscan.auth import AuthStore

    auth = AuthStore(database)
    user = auth.register("legacy@example.test", "correct-horse-battery")

    plans = PlanStore(database)
    assert plans.get(user.id) == "free"
    plans.migrate()
    assert plans.get(user.id) == "free"
