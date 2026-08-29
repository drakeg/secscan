from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from secscan.auth import AuthStore
from secscan.billing import (
    BillingConfig,
    BillingError,
    BillingStore,
    StripeBillingClient,
    verify_stripe_event,
)
from secscan.public_site import PlanStore


def _event(event_id: str, event_type: str, obj: dict[str, object]) -> dict[str, object]:
    return {"id": event_id, "type": event_type, "data": {"object": obj}}


def _signature(payload: bytes, secret: str, timestamp: int) -> str:
    digest = hmac.new(
        secret.encode(), str(timestamp).encode() + b"." + payload, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_billing_configuration_is_disabled_when_empty_and_fails_on_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "SECSCAN_STRIPE_SECRET_KEY",
        "SECSCAN_STRIPE_WEBHOOK_SECRET",
        "SECSCAN_STRIPE_PROFESSIONAL_PRICE_ID",
        "SECSCAN_PUBLIC_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    assert BillingConfig.from_environment() is None

    monkeypatch.setenv("SECSCAN_STRIPE_SECRET_KEY", "sk_test_example")
    with pytest.raises(BillingError, match="incomplete"):
        BillingConfig.from_environment()


def test_webhook_signature_verification_checks_signature_and_recency() -> None:
    payload = json.dumps({"id": "evt_1", "type": "test", "data": {"object": {}}}).encode()
    secret = "whsec_example"
    header = _signature(payload, secret, 1_000)

    assert verify_stripe_event(payload, header, secret, now=1_100)["id"] == "evt_1"
    with pytest.raises(BillingError, match="outside the allowed tolerance"):
        verify_stripe_event(payload, header, secret, now=1_301)
    with pytest.raises(BillingError, match="verification failed"):
        verify_stripe_event(payload, header.replace("v1=", "v1=bad"), secret, now=1_100)


def test_subscription_events_are_idempotent_and_drive_entitlement(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    plans = PlanStore(database)
    user = auth.register("billing@example.test", "correct-horse-battery")
    plans.set(user.id, "professional")

    billing = BillingStore(database)
    assert plans.get(user.id) == "free"

    checkout = _event(
        "evt_checkout",
        "checkout.session.completed",
        {
            "client_reference_id": user.tenant_id,
            "customer": "cus_123",
            "subscription": "sub_123",
        },
    )
    checkout_state = billing.apply_stripe_event(checkout)
    assert checkout_state is not None
    assert checkout_state.status == "checkout_complete"
    assert plans.get(user.id) == "free"

    active = _event(
        "evt_active",
        "customer.subscription.updated",
        {
            "id": "sub_123",
            "customer": "cus_123",
            "status": "active",
            "current_period_end": 2_000_000_000,
            "metadata": {"secscan_tenant_id": user.tenant_id},
        },
    )
    active_state = billing.apply_stripe_event(active)
    assert active_state is not None and active_state.professional_active
    assert plans.get(user.id) == "professional"
    assert billing.apply_stripe_event(active) is None
    assert plans.get(user.id) == "professional"

    failed = _event(
        "evt_failed",
        "invoice.payment_failed",
        {"subscription": "sub_123"},
    )
    failed_state = billing.apply_stripe_event(failed)
    assert failed_state is not None
    assert failed_state.status == "payment_failed"
    assert plans.get(user.id) == "free"


def test_canceled_subscription_removes_professional_entitlement(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    auth = AuthStore(database)
    plans = PlanStore(database)
    user = auth.register("cancel@example.test", "correct-horse-battery")
    billing = BillingStore(database)

    billing.apply_stripe_event(
        _event(
            "evt_active",
            "customer.subscription.created",
            {
                "id": "sub_cancel",
                "customer": "cus_cancel",
                "status": "trialing",
                "metadata": {"secscan_tenant_id": user.tenant_id},
            },
        )
    )
    assert plans.get(user.id) == "professional"

    billing.apply_stripe_event(
        _event(
            "evt_deleted",
            "customer.subscription.deleted",
            {
                "id": "sub_cancel",
                "customer": "cus_cancel",
                "status": "canceled",
                "metadata": {"secscan_tenant_id": user.tenant_id},
            },
        )
    )
    assert plans.get(user.id) == "free"


def test_checkout_uses_fixed_subscription_fields_and_server_price() -> None:
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"id":"cs_test","url":"https://checkout.stripe.test/session"}'

    def opener(request, *, timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = request.full_url
        captured["authorization"] = request.headers["Authorization"]
        captured["fields"] = parse_qs(request.data.decode())
        captured["timeout"] = timeout
        return Response()

    client = StripeBillingClient(
        BillingConfig(
            secret_key="sk_test_example",
            webhook_secret="whsec_example",
            professional_price_id="price_professional",
            public_base_url="https://secscan.example.test",
        ),
        opener=opener,
    )
    session = client.create_checkout_session(
        tenant_id="tenant-1", email="user@example.test", customer_id=None
    )

    assert session["id"] == "cs_test"
    assert captured["url"] == "https://api.stripe.com/v1/checkout/sessions"
    assert captured["authorization"] == "Bearer sk_test_example"
    fields = captured["fields"]
    assert isinstance(fields, dict)
    assert fields["mode"] == ["subscription"]
    assert fields["line_items[0][price]"] == ["price_professional"]
    assert fields["client_reference_id"] == ["tenant-1"]
    assert fields["subscription_data[metadata][secscan_tenant_id]"] == ["tenant-1"]
    assert "card" not in " ".join(fields)
