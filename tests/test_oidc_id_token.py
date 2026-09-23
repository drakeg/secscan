from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from secscan.oidc import (
    ConsumedOidcLoginTransaction,
    OIDC_JWKS_MAX_BYTES,
    OIDC_JWKS_TIMEOUT_SECONDS,
    OidcDiscoveryDocument,
    OidcLoginTransactionStore,
    OidcProviderConfig,
    fetch_oidc_jwks,
    verify_oidc_id_token,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _config() -> OidcProviderConfig:
    config = OidcProviderConfig.from_environment(
        {
            "SECSCAN_OIDC_ISSUER": "https://login.example.com/tenant",
            "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
            "SECSCAN_OIDC_CLIENT_SECRET": "secret",
        }
    )
    assert config is not None
    return config


def _discovery() -> OidcDiscoveryDocument:
    return OidcDiscoveryDocument.from_mapping(
        _config(),
        {
            "issuer": "https://login.example.com/tenant",
            "authorization_endpoint": "https://login.example.com/oauth2/authorize",
            "token_endpoint": "https://login.example.com/oauth2/token",
            "jwks_uri": "https://login.example.com/oauth2/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
        },
    )


def _jwk(private_key: rsa.RSAPrivateKey, *, kid: str = "key-1", alg: str = "RS256") -> dict[str, str]:
    public = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": _b64url(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
    }


def _token(
    private_key: rsa.RSAPrivateKey,
    *,
    now: datetime,
    kid: str = "key-1",
    alg: str = "RS256",
    issuer: str = "https://login.example.com/tenant",
    audience: object = "secscan-web",
    subject: str = "subject-123",
    nonce: str,
    expires_delta: timedelta = timedelta(minutes=5),
    azp: str | None = None,
) -> str:
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    payload: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": int((now + expires_delta).timestamp()),
        "nonce": nonce,
    }
    if azp is not None:
        payload["azp"] = azp
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    hash_algorithm = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }[alg]
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hash_algorithm)
    return f"{encoded_header}.{encoded_payload}.{_b64url(signature)}"


def _transaction(tmp_path: Path, now: datetime) -> tuple[str, ConsumedOidcLoginTransaction]:
    issued = OidcLoginTransactionStore(tmp_path / "jobs.db").create(now=now)
    consumed = OidcLoginTransactionStore(tmp_path / "jobs.db").consume(
        issued.state,
        now=now + timedelta(seconds=1),
    )
    return issued.nonce, consumed


def test_fetch_oidc_jwks_uses_bounded_json_retrieval() -> None:
    discovery = _discovery()
    observed: dict[str, object] = {}
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = json.dumps({"keys": [_jwk(key)]}).encode("utf-8")

    def fetcher(url: str, max_bytes: int, timeout: float) -> tuple[str, bytes]:
        observed.update(url=url, max_bytes=max_bytes, timeout=timeout)
        return "application/json", body

    jwks = fetch_oidc_jwks(discovery, fetcher=fetcher)
    assert jwks["keys"]
    assert observed == {
        "url": discovery.jwks_uri,
        "max_bytes": OIDC_JWKS_MAX_BYTES,
        "timeout": OIDC_JWKS_TIMEOUT_SECONDS,
    }


def test_fetch_oidc_jwks_rejects_non_json_oversize_and_missing_keys() -> None:
    discovery = _discovery()
    with pytest.raises(ValueError, match="must be JSON"):
        fetch_oidc_jwks(
            discovery,
            fetcher=lambda _url, _max, _timeout: ("text/html", b"{}"),
        )
    with pytest.raises(ValueError, match="exceeds size limit"):
        fetch_oidc_jwks(
            discovery,
            fetcher=lambda _url, _max, _timeout: (
                "application/json",
                b"x" * (OIDC_JWKS_MAX_BYTES + 1),
            ),
        )
    with pytest.raises(ValueError, match="must contain keys"):
        fetch_oidc_jwks(
            discovery,
            fetcher=lambda _url, _max, _timeout: ("application/json", b'{"keys":[]}'),
        )


@pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512"])
def test_verify_oidc_id_token_accepts_valid_rsa_signatures(
    tmp_path: Path,
    algorithm: str,
) -> None:
    now = datetime(2026, 9, 22, 22, 0, tzinfo=UTC)
    nonce, transaction = _transaction(tmp_path, now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _token(key, now=now, nonce=nonce, alg=algorithm)
    identity = verify_oidc_id_token(
        token,
        config=_config(),
        discovery=_discovery(),
        jwks={"keys": [_jwk(key, alg=algorithm)]},
        transaction=transaction,
        now=now + timedelta(seconds=2),
    )
    assert identity.issuer == "https://login.example.com/tenant"
    assert identity.subject == "subject-123"


def test_verify_oidc_id_token_rejects_tampering_wrong_key_and_unadvertised_algorithm(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 9, 22, 22, 0, tzinfo=UTC)
    nonce, transaction = _transaction(tmp_path, now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _token(key, now=now, nonce=nonce)

    parts = token.split(".")
    tampered_payload = _b64url(
        json.dumps(
            {
                "iss": "https://login.example.com/tenant",
                "sub": "attacker",
                "aud": "secscan-web",
                "exp": int((now + timedelta(minutes=5)).timestamp()),
                "nonce": nonce,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    tampered = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_oidc_id_token(
            tampered,
            config=_config(),
            discovery=_discovery(),
            jwks={"keys": [_jwk(key)]},
            transaction=transaction,
            now=now,
        )

    with pytest.raises(ValueError, match="signing key was not found"):
        verify_oidc_id_token(
            token,
            config=_config(),
            discovery=_discovery(),
            jwks={"keys": [_jwk(other, kid="other")]},
            transaction=transaction,
            now=now,
        )

    limited = OidcDiscoveryDocument.from_mapping(
        _config(),
        {
            "issuer": "https://login.example.com/tenant",
            "authorization_endpoint": "https://login.example.com/oauth2/authorize",
            "token_endpoint": "https://login.example.com/oauth2/token",
            "jwks_uri": "https://login.example.com/oauth2/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
    )
    rs512 = _token(key, now=now, nonce=nonce, alg="RS512")
    with pytest.raises(ValueError, match="not advertised"):
        verify_oidc_id_token(
            rs512,
            config=_config(),
            discovery=limited,
            jwks={"keys": [_jwk(key, alg="RS512")]},
            transaction=transaction,
            now=now,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"issuer": "https://login.example.com/other"}, "issuer is invalid"),
        ({"audience": "other-client"}, "audience is invalid"),
        ({"expires_delta": timedelta(seconds=-1)}, "expired"),
        ({"nonce": "wrong-nonce"}, "nonce is invalid"),
    ],
)
def test_verify_oidc_id_token_rejects_invalid_claims(
    tmp_path: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    now = datetime(2026, 9, 22, 22, 0, tzinfo=UTC)
    nonce, transaction = _transaction(tmp_path, now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    arguments: dict[str, object] = {"now": now, "nonce": nonce}
    arguments.update(overrides)
    token = _token(key, **arguments)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=message):
        verify_oidc_id_token(
            token,
            config=_config(),
            discovery=_discovery(),
            jwks={"keys": [_jwk(key)]},
            transaction=transaction,
            now=now,
        )


def test_verify_oidc_id_token_requires_azp_for_multiple_audiences(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 22, 0, tzinfo=UTC)
    nonce, transaction = _transaction(tmp_path, now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    invalid = _token(
        key,
        now=now,
        nonce=nonce,
        audience=["secscan-web", "other-client"],
    )
    with pytest.raises(ValueError, match="authorized party"):
        verify_oidc_id_token(
            invalid,
            config=_config(),
            discovery=_discovery(),
            jwks={"keys": [_jwk(key)]},
            transaction=transaction,
            now=now,
        )

    valid = _token(
        key,
        now=now,
        nonce=nonce,
        audience=["secscan-web", "other-client"],
        azp="secscan-web",
    )
    identity = verify_oidc_id_token(
        valid,
        config=_config(),
        discovery=_discovery(),
        jwks={"keys": [_jwk(key)]},
        transaction=transaction,
        now=now,
    )
    assert identity.subject == "subject-123"


def test_verify_oidc_id_token_rejects_small_rsa_key(tmp_path: Path) -> None:
    now = datetime(2026, 9, 22, 22, 0, tzinfo=UTC)
    nonce, transaction = _transaction(tmp_path, now)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    token = _token(key, now=now, nonce=nonce)

    with pytest.raises(ValueError, match="RSA key is invalid"):
        verify_oidc_id_token(
            token,
            config=_config(),
            discovery=_discovery(),
            jwks={"keys": [_jwk(key)]},
            transaction=transaction,
            now=now,
        )
