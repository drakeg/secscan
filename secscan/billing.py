from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen


ACTIVE_SUBSCRIPTION_STATUSES = frozenset({"active", "trialing"})
STRIPE_API_BASE = "https://api.stripe.com/v1"
STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300


class BillingError(RuntimeError):
    pass


@dataclass(frozen=True)
class BillingConfig:
    secret_key: str
    webhook_secret: str
    professional_price_id: str
    public_base_url: str

    @classmethod
    def from_environment(cls) -> BillingConfig | None:
        values = {
            "secret_key": os.environ.get("SECSCAN_STRIPE_SECRET_KEY", "").strip(),
            "webhook_secret": os.environ.get("SECSCAN_STRIPE_WEBHOOK_SECRET", "").strip(),
            "professional_price_id": os.environ.get(
                "SECSCAN_STRIPE_PROFESSIONAL_PRICE_ID", ""
            ).strip(),
            "public_base_url": os.environ.get("SECSCAN_PUBLIC_BASE_URL", "").strip().rstrip("/"),
        }
        if not any(values.values()):
            return None
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise BillingError(
                "Stripe billing configuration is incomplete; missing " + ", ".join(sorted(missing))
            )
        public_base_url = values["public_base_url"]
        if not public_base_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise BillingError(
                "SECSCAN_PUBLIC_BASE_URL must use HTTPS, except localhost/127.0.0.1 development URLs"
            )
        return cls(**values)


@dataclass(frozen=True)
class BillingState:
    tenant_id: str
    provider: str
    customer_id: str | None
    subscription_id: str | None
    status: str
    current_period_end: int | None

    @property
    def professional_active(self) -> bool:
        return self.status in ACTIVE_SUBSCRIPTION_STATUSES


class BillingStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS billing_subscriptions (
                    tenant_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL CHECK(provider = 'stripe'),
                    customer_id TEXT,
                    subscription_id TEXT UNIQUE,
                    status TEXT NOT NULL,
                    current_period_end INTEGER,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS billing_subscriptions_customer_idx
                    ON billing_subscriptions(customer_id);
                CREATE TABLE IF NOT EXISTS billing_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
                """
            )
            # Sprint 52 Professional access was explicitly a no-charge preview. Once
            # enforced billing exists, preview rows must not remain an entitlement bypass.
            connection.execute(
                """
                UPDATE auth_users SET plan = 'free'
                WHERE plan = 'professional'
                  AND tenant_id NOT IN (
                      SELECT tenant_id FROM billing_subscriptions
                      WHERE status IN ('active', 'trialing')
                  )
                """
            )

    def state(self, tenant_id: str) -> BillingState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM billing_subscriptions WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
        if row is None:
            return BillingState(tenant_id, "stripe", None, None, "none", None)
        return _state(row)

    def apply_stripe_event(self, event: dict[str, Any]) -> BillingState | None:
        event_id = _required_string(event, "id")
        event_type = _required_string(event, "type")
        data = event.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("object"), dict):
            raise BillingError("Stripe event data.object must be an object")
        obj = data["object"]
        assert isinstance(obj, dict)

        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM billing_events WHERE event_id = ?", (event_id,)
            ).fetchone():
                return None

            state: BillingState | None = None
            if event_type == "checkout.session.completed":
                tenant_id = _tenant_from_object(obj)
                if tenant_id is None:
                    raise BillingError("Stripe Checkout event is missing secscan tenant identity")
                customer_id = _optional_identifier(obj.get("customer"))
                subscription_id = _optional_identifier(obj.get("subscription"))
                state = self._upsert(
                    connection,
                    tenant_id=tenant_id,
                    customer_id=customer_id,
                    subscription_id=subscription_id,
                    status="checkout_complete",
                    current_period_end=None,
                )
            elif event_type in {
                "customer.subscription.created",
                "customer.subscription.updated",
                "customer.subscription.deleted",
            }:
                subscription_id = _required_string(obj, "id")
                tenant_id = _tenant_from_object(obj) or self._tenant_for_subscription(
                    connection, subscription_id
                )
                if tenant_id is None:
                    raise BillingError("Stripe subscription event is missing secscan tenant identity")
                status = "canceled" if event_type == "customer.subscription.deleted" else _required_string(obj, "status")
                state = self._upsert(
                    connection,
                    tenant_id=tenant_id,
                    customer_id=_optional_identifier(obj.get("customer")),
                    subscription_id=subscription_id,
                    status=status,
                    current_period_end=_optional_int(obj.get("current_period_end")),
                )
                self._set_entitlement(connection, tenant_id, state.professional_active)
            elif event_type == "invoice.payment_failed":
                subscription_id = _invoice_subscription_id(obj)
                if subscription_id:
                    tenant_id = self._tenant_for_subscription(connection, subscription_id)
                    if tenant_id:
                        previous = self._state_for_connection(connection, tenant_id)
                        state = self._upsert(
                            connection,
                            tenant_id=tenant_id,
                            customer_id=previous.customer_id,
                            subscription_id=subscription_id,
                            status="payment_failed",
                            current_period_end=previous.current_period_end,
                        )
                        self._set_entitlement(connection, tenant_id, False)

            connection.execute(
                "INSERT INTO billing_events (event_id, event_type, processed_at) VALUES (?, ?, ?)",
                (event_id, event_type, datetime.now(UTC).isoformat()),
            )
            return state

    def _state_for_connection(self, connection: sqlite3.Connection, tenant_id: str) -> BillingState:
        row = connection.execute(
            "SELECT * FROM billing_subscriptions WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        return _state(row) if row else BillingState(tenant_id, "stripe", None, None, "none", None)

    def _tenant_for_subscription(
        self, connection: sqlite3.Connection, subscription_id: str
    ) -> str | None:
        row = connection.execute(
            "SELECT tenant_id FROM billing_subscriptions WHERE subscription_id = ?",
            (subscription_id,),
        ).fetchone()
        return str(row["tenant_id"]) if row else None

    def _upsert(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        customer_id: str | None,
        subscription_id: str | None,
        status: str,
        current_period_end: int | None,
    ) -> BillingState:
        existing = self._state_for_connection(connection, tenant_id)
        customer = customer_id or existing.customer_id
        subscription = subscription_id or existing.subscription_id
        connection.execute(
            """
            INSERT INTO billing_subscriptions
                (tenant_id, provider, customer_id, subscription_id, status, current_period_end, updated_at)
            VALUES (?, 'stripe', ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                customer_id = excluded.customer_id,
                subscription_id = excluded.subscription_id,
                status = excluded.status,
                current_period_end = excluded.current_period_end,
                updated_at = excluded.updated_at
            """,
            (
                tenant_id,
                customer,
                subscription,
                status,
                current_period_end,
                datetime.now(UTC).isoformat(),
            ),
        )
        return BillingState(
            tenant_id,
            "stripe",
            customer,
            subscription,
            status,
            current_period_end,
        )

    @staticmethod
    def _set_entitlement(
        connection: sqlite3.Connection, tenant_id: str, professional_active: bool
    ) -> None:
        connection.execute(
            "UPDATE auth_users SET plan = ? WHERE tenant_id = ?",
            ("professional" if professional_active else "free", tenant_id),
        )


class StripeBillingClient:
    def __init__(
        self,
        config: BillingConfig,
        *,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.config = config
        self._opener = opener

    def create_checkout_session(
        self,
        *,
        tenant_id: str,
        email: str,
        customer_id: str | None,
    ) -> dict[str, Any]:
        fields: list[tuple[str, str]] = [
            ("mode", "subscription"),
            ("client_reference_id", tenant_id),
            ("line_items[0][price]", self.config.professional_price_id),
            ("line_items[0][quantity]", "1"),
            ("success_url", f"{self.config.public_base_url}/account/plan?checkout=success"),
            ("cancel_url", f"{self.config.public_base_url}/account/plan?checkout=cancelled"),
            ("metadata[secscan_tenant_id]", tenant_id),
            ("subscription_data[metadata][secscan_tenant_id]", tenant_id),
        ]
        if customer_id:
            fields.append(("customer", customer_id))
        else:
            fields.append(("customer_email", email))
        payload = self._post("/checkout/sessions", fields)
        if not isinstance(payload.get("id"), str) or not isinstance(payload.get("url"), str):
            raise BillingError("Stripe Checkout response did not contain id and url")
        return payload

    def create_portal_session(self, customer_id: str) -> dict[str, Any]:
        payload = self._post(
            "/billing_portal/sessions",
            [
                ("customer", customer_id),
                ("return_url", f"{self.config.public_base_url}/account/plan"),
            ],
        )
        if not isinstance(payload.get("url"), str):
            raise BillingError("Stripe billing portal response did not contain a url")
        return payload

    def _post(self, path: str, fields: list[tuple[str, str]]) -> dict[str, Any]:
        request = UrlRequest(
            STRIPE_API_BASE + path,
            data=urlencode(fields).encode(),
            headers={
                "Authorization": f"Bearer {self.config.secret_key}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=15) as response:
                payload = json.loads(response.read())
        except HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise BillingError(f"Stripe API request failed with HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError) as exc:
            raise BillingError(f"Stripe API request failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise BillingError("Stripe API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise BillingError("Stripe API returned an unexpected response")
        return payload


def verify_stripe_event(
    payload: bytes,
    signature_header: str,
    webhook_secret: str,
    *,
    now: int | None = None,
    tolerance_seconds: int = STRIPE_SIGNATURE_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    timestamp: int | None = None
    signatures: list[str] = []
    for component in signature_header.split(","):
        name, separator, value = component.strip().partition("=")
        if not separator:
            continue
        if name == "t":
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise BillingError("Stripe signature timestamp is invalid") from exc
        elif name == "v1":
            signatures.append(value)
    if timestamp is None or not signatures:
        raise BillingError("Stripe-Signature must contain timestamp and v1 signature")
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance_seconds:
        raise BillingError("Stripe webhook signature timestamp is outside the allowed tolerance")
    signed_payload = str(timestamp).encode() + b"." + payload
    expected = hmac.new(webhook_secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise BillingError("Stripe webhook signature verification failed")
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise BillingError("Stripe webhook payload is invalid JSON") from exc
    if not isinstance(event, dict):
        raise BillingError("Stripe webhook payload must be a JSON object")
    return event


def _state(row: sqlite3.Row) -> BillingState:
    return BillingState(
        tenant_id=str(row["tenant_id"]),
        provider=str(row["provider"]),
        customer_id=str(row["customer_id"]) if row["customer_id"] is not None else None,
        subscription_id=(
            str(row["subscription_id"]) if row["subscription_id"] is not None else None
        ),
        status=str(row["status"]),
        current_period_end=(
            int(row["current_period_end"]) if row["current_period_end"] is not None else None
        ),
    )


def _required_string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise BillingError(f"Stripe document is missing {key}")
    return value


def _optional_identifier(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return str(value["id"])
    return None


def _optional_int(value: Any) -> int | None:
    return int(value) if isinstance(value, int) else None


def _tenant_from_object(document: dict[str, Any]) -> str | None:
    client_reference_id = document.get("client_reference_id")
    if isinstance(client_reference_id, str) and client_reference_id:
        return client_reference_id
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        tenant_id = metadata.get("secscan_tenant_id")
        if isinstance(tenant_id, str) and tenant_id:
            return tenant_id
    return None


def _invoice_subscription_id(document: dict[str, Any]) -> str | None:
    direct = _optional_identifier(document.get("subscription"))
    if direct:
        return direct
    parent = document.get("parent")
    if isinstance(parent, dict):
        details = parent.get("subscription_details")
        if isinstance(details, dict):
            return _optional_identifier(details.get("subscription"))
    return None
