from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import Request

import pytest

from secscan.oidc import (
    OIDC_DISCOVERY_MAX_BYTES,
    OIDC_DISCOVERY_TIMEOUT_SECONDS,
    OidcProviderConfig,
    fetch_oidc_discovery,
    oidc_discovery_url,
)


def _config(issuer: str = "https://login.example.com/tenant") -> OidcProviderConfig:
    config = OidcProviderConfig.from_environment(
        {
            "SECSCAN_OIDC_ISSUER": issuer,
            "SECSCAN_OIDC_CLIENT_ID": "secscan-web",
            "SECSCAN_OIDC_CLIENT_SECRET": "secret",
        }
    )
    assert config is not None
    return config


def _document(issuer: str = "https://login.example.com/tenant") -> bytes:
    return (
        "{"
        f'"issuer":"{issuer}",'
        '"authorization_endpoint":"https://login.example.com/oauth2/authorize",'
        '"token_endpoint":"https://login.example.com/oauth2/token",'
        '"jwks_uri":"https://login.example.com/oauth2/jwks",'
        '"response_types_supported":["code"],'
        '"id_token_signing_alg_values_supported":["RS256"]'
        "}"
    ).encode("utf-8")


def test_oidc_discovery_url_follows_well_known_path_rules() -> None:
    assert oidc_discovery_url("https://login.example.com") == (
        "https://login.example.com/.well-known/openid-configuration"
    )
    assert oidc_discovery_url("https://login.example.com/tenant") == (
        "https://login.example.com/.well-known/openid-configuration/tenant"
    )
    assert oidc_discovery_url("https://login.example.com/tenant/") == (
        "https://login.example.com/.well-known/openid-configuration/tenant/"
    )


def test_fetch_oidc_discovery_passes_strict_bounds_to_fetcher() -> None:
    config = _config()
    observed: dict[str, object] = {}

    def fetcher(url: str, max_bytes: int, timeout: float) -> tuple[str, bytes]:
        observed.update(url=url, max_bytes=max_bytes, timeout=timeout)
        return "application/json; charset=utf-8", _document()

    discovery = fetch_oidc_discovery(config, fetcher=fetcher)
    assert discovery.issuer == config.issuer
    assert observed == {
        "url": "https://login.example.com/.well-known/openid-configuration/tenant",
        "max_bytes": OIDC_DISCOVERY_MAX_BYTES,
        "timeout": OIDC_DISCOVERY_TIMEOUT_SECONDS,
    }


@pytest.mark.parametrize(
    "content_type",
    ["text/html", "text/plain", "", "application/xml"],
)
def test_fetch_oidc_discovery_rejects_non_json_content_type(content_type: str) -> None:
    with pytest.raises(ValueError, match="must be JSON"):
        fetch_oidc_discovery(
            _config(),
            fetcher=lambda _url, _max, _timeout: (content_type, _document()),
        )


def test_fetch_oidc_discovery_accepts_structured_json_media_type() -> None:
    discovery = fetch_oidc_discovery(
        _config(),
        fetcher=lambda _url, _max, _timeout: (
            "application/openid-configuration+json",
            _document(),
        ),
    )
    assert discovery.issuer == "https://login.example.com/tenant"


def test_fetch_oidc_discovery_rejects_oversized_invalid_and_non_object_json() -> None:
    config = _config()

    with pytest.raises(ValueError, match="exceeds size limit"):
        fetch_oidc_discovery(
            config,
            fetcher=lambda _url, _max, _timeout: (
                "application/json",
                b"x" * (OIDC_DISCOVERY_MAX_BYTES + 1),
            ),
        )

    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        fetch_oidc_discovery(
            config,
            fetcher=lambda _url, _max, _timeout: ("application/json", b"{not-json"),
        )

    with pytest.raises(ValueError, match="JSON object"):
        fetch_oidc_discovery(
            config,
            fetcher=lambda _url, _max, _timeout: ("application/json", b"[]"),
        )


def test_fetch_oidc_discovery_still_validates_document_issuer() -> None:
    with pytest.raises(ValueError, match="issuer does not match"):
        fetch_oidc_discovery(
            _config(),
            fetcher=lambda _url, _max, _timeout: (
                "application/json",
                _document("https://login.example.com/other"),
            ),
        )


def test_default_fetcher_disables_redirects(monkeypatch) -> None:
    from secscan import oidc

    class RedirectingOpener:
        def open(self, request: Request, timeout: float):  # noqa: ANN001
            raise HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": "https://evil.example.com/.well-known/openid-configuration"},
                None,
            )

    monkeypatch.setattr(oidc, "build_opener", lambda *_handlers: RedirectingOpener())

    with pytest.raises(ValueError, match="redirects are not allowed"):
        fetch_oidc_discovery(_config())
