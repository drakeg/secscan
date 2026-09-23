from __future__ import annotations

import base64
from urllib.parse import parse_qs

import pytest

from secscan.oidc import (
    OIDC_TOKEN_MAX_BYTES,
    OIDC_TOKEN_TIMEOUT_SECONDS,
    OidcDiscoveryDocument,
    OidcProviderConfig,
    exchange_oidc_code,
)


def _config() -> OidcProviderConfig:
    config = OidcProviderConfig.from_environment(
        {
            "SECSCAN_OIDC_ISSUER": "https://login.example.com/tenant",
            "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
            "SECSCAN_OIDC_CLIENT_SECRET": "super-secret",
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
            "id_token_signing_alg_values_supported": ["RS256"],
        },
    )


def test_exchange_oidc_code_uses_post_form_and_basic_client_auth() -> None:
    observed: dict[str, object] = {}

    def exchanger(
        url: str,
        body: bytes,
        authorization: str,
        max_bytes: int,
        timeout: float,
    ) -> tuple[str, bytes]:
        observed.update(
            url=url,
            body=body,
            authorization=authorization,
            max_bytes=max_bytes,
            timeout=timeout,
        )
        return "application/json; charset=utf-8", b'{"id_token":"header.payload.signature"}'

    response = exchange_oidc_code(
        _config(),
        _discovery(),
        code="authorization-code-123",
        redirect_uri="https://secscan.example.com/api/v1/auth/oidc/callback",
        exchanger=exchanger,
    )
    assert response.id_token == "header.payload.signature"
    assert observed["url"] == "https://login.example.com/oauth2/token"
    assert observed["max_bytes"] == OIDC_TOKEN_MAX_BYTES
    assert observed["timeout"] == OIDC_TOKEN_TIMEOUT_SECONDS
    assert parse_qs(bytes(observed["body"]).decode("ascii")) == {
        "grant_type": ["authorization_code"],
        "code": ["authorization-code-123"],
        "redirect_uri": ["https://secscan.example.com/api/v1/auth/oidc/callback"],
    }
    expected = base64.b64encode(b"secscan-web:super-secret").decode("ascii")
    assert observed["authorization"] == f"Basic {expected}"
    assert b"super-secret" not in bytes(observed["body"])


@pytest.mark.parametrize("content_type", ["text/html", "text/plain", ""])
def test_exchange_oidc_code_rejects_non_json_response(content_type: str) -> None:
    with pytest.raises(ValueError, match="must be JSON"):
        exchange_oidc_code(
            _config(),
            _discovery(),
            code="authorization-code-123",
            redirect_uri="https://secscan.example.com/callback",
            exchanger=lambda *_args: (content_type, b'{"id_token":"token"}'),
        )


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"[]", "JSON object"),
        (b"{not-json", "valid UTF-8 JSON"),
        (b"{}", "valid id_token"),
        (b'{"id_token":""}', "valid id_token"),
    ],
)
def test_exchange_oidc_code_rejects_invalid_token_response(body: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        exchange_oidc_code(
            _config(),
            _discovery(),
            code="authorization-code-123",
            redirect_uri="https://secscan.example.com/callback",
            exchanger=lambda *_args: ("application/json", body),
        )


def test_exchange_oidc_code_rejects_oversized_response() -> None:
    with pytest.raises(ValueError, match="exceeds size limit"):
        exchange_oidc_code(
            _config(),
            _discovery(),
            code="authorization-code-123",
            redirect_uri="https://secscan.example.com/callback",
            exchanger=lambda *_args: (
                "application/json",
                b"x" * (OIDC_TOKEN_MAX_BYTES + 1),
            ),
        )


@pytest.mark.parametrize("code", ["", "contains space", "line\nbreak"])
def test_exchange_oidc_code_rejects_malformed_authorization_code(code: str) -> None:
    with pytest.raises(ValueError, match="authorization code is invalid"):
        exchange_oidc_code(
            _config(),
            _discovery(),
            code=code,
            redirect_uri="https://secscan.example.com/callback",
            exchanger=lambda *_args: ("application/json", b'{"id_token":"token"}'),
        )


def test_exchange_oidc_code_rejects_insecure_redirect_uri() -> None:
    with pytest.raises(ValueError, match="absolute HTTPS"):
        exchange_oidc_code(
            _config(),
            _discovery(),
            code="authorization-code-123",
            redirect_uri="http://secscan.example.com/callback",
            exchanger=lambda *_args: ("application/json", b'{"id_token":"token"}'),
        )
