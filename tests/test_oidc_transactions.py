from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
import threading

import pytest

from secscan.oidc import OidcLoginTransactionStore


def test_oidc_login_transaction_is_single_use_and_nonce_bound(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    store = OidcLoginTransactionStore(database)
    now = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)

    issued = store.create(now=now)
    assert issued.state
    assert issued.nonce
    assert issued.state != issued.nonce

    consumed = store.consume(issued.state, now=now + timedelta(minutes=1))
    assert consumed.matches_nonce(issued.nonce) is True
    assert consumed.matches_nonce("wrong-nonce") is False

    with pytest.raises(ValueError, match="invalid or expired"):
        store.consume(issued.state, now=now + timedelta(minutes=1))


def test_oidc_login_transaction_expires_and_is_consumed_on_failure(tmp_path: Path) -> None:
    store = OidcLoginTransactionStore(tmp_path / "jobs.db")
    now = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
    issued = store.create(now=now)

    with pytest.raises(ValueError, match="invalid or expired"):
        store.consume(issued.state, now=now + timedelta(minutes=11))

    with pytest.raises(ValueError, match="invalid or expired"):
        store.consume(issued.state, now=now + timedelta(minutes=1))


def test_oidc_login_transaction_persists_only_state_and_nonce_digests(tmp_path: Path) -> None:
    database = tmp_path / "jobs.db"
    store = OidcLoginTransactionStore(database)
    issued = store.create(now=datetime(2026, 9, 19, 14, 0, tzinfo=UTC))

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT state_digest, nonce_digest FROM auth_oidc_login_transactions"
        ).fetchone()
    assert row is not None
    state_digest, nonce_digest = str(row[0]), str(row[1])
    assert issued.state not in {state_digest, nonce_digest}
    assert issued.nonce not in {state_digest, nonce_digest}
    assert len(state_digest) == 64
    assert len(nonce_digest) == 64


def test_oidc_login_transaction_rejects_malformed_state_and_nonce(tmp_path: Path) -> None:
    store = OidcLoginTransactionStore(tmp_path / "jobs.db")
    issued = store.create(now=datetime(2026, 9, 19, 14, 0, tzinfo=UTC))
    consumed = store.consume(issued.state, now=datetime(2026, 9, 19, 14, 1, tzinfo=UTC))

    for invalid in ("", "contains space", "line\nbreak"):
        with pytest.raises(ValueError, match="OIDC nonce is invalid"):
            consumed.matches_nonce(invalid)

    for invalid in ("", "contains space", "line\nbreak"):
        with pytest.raises(ValueError, match="OIDC state is invalid"):
            store.consume(invalid)


def test_oidc_login_transaction_requires_timezone_aware_time(tmp_path: Path) -> None:
    store = OidcLoginTransactionStore(tmp_path / "jobs.db")
    with pytest.raises(ValueError, match="timezone-aware"):
        store.create(now=datetime(2026, 9, 19, 14, 0))


def test_oidc_login_transaction_allows_only_one_concurrent_consumer(tmp_path: Path) -> None:
    store = OidcLoginTransactionStore(tmp_path / "jobs.db")
    now = datetime(2026, 9, 19, 14, 0, tzinfo=UTC)
    issued = store.create(now=now)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def consume() -> None:
        barrier.wait()
        try:
            store.consume(issued.state, now=now + timedelta(seconds=1))
        except ValueError:
            outcome = "rejected"
        else:
            outcome = "consumed"
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert sorted(outcomes) == ["consumed", "rejected"]
