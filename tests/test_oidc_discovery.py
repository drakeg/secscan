from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from secscan.oidc import (
    OidcDiscoveryDocument,
    OidcLoginTransactionStore,
    OidcProviderConfig,
)


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


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": "https://login.example.com/tenant",
        "authorization_endpoint": "https://login.example.com/oauth2/authorize",
        "token_endpoint": "https://login.example.com/oauth2/token",
        "jwks_uri": "https://login.example.com/oauth2/jwks",
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    document.update(overrides)
    return document


def test_oidc_discovery_requires_exact_issuer_and_code_flow() -> None:
    config = _config()
    discovery = OidcDiscoveryDocument.from_mapping(config, _document())
    assert discovery.issuer == config.issuer
    assert discovery.id_token_signing_alg_values_supported == ("RS256",)

    with pytest.raises(ValueError, match="issuer does not match"):
        OidcDiscoveryDocument.from_mapping(
            config,
            _document(issuer="https://login.example.com/tenant/"),
        )

    with pytest.raises(ValueError, match="authorization code flow"):
        OidcDiscoveryDocument.from_mapping(
            config,
            _document(response_types_supported=["id_token"]),
        )


@pytest.mark.parametrize(
    "field",
    ["authorization_endpoint", "token_endpoint", "jwks_uri"],
)
def test_oidc_discovery_rejects_insecure_provider_endpoints(field: str) -> None:
    config = _config()
    with pytest.raises(ValueError, match="must use HTTPS"):
        OidcDiscoveryDocument.from_mapping(
            config,
            _document(**{field: "http://login.example.com/insecure"}),
        )


def test_oidc_discovery_requires_signed_id_token_algorithm() -> None:
    config = _config()
    with pytest.raises(ValueError, match="signed ID-token"):
        OidcDiscoveryDocument.from_mapping(
            config,
            _document(id_token_signing_alg_values_supported=["none"]),
        )


def test_authorization_url_is_built_only_from_validated_metadata(tmp_path: Path) -> None:
    config = _config()
    discovery = OidcDiscoveryDocument.from_mapping(config, _document())
    transaction = OidcLoginTransactionStore(tmp_path / "jobs.db").create()

    url = discovery.authorization_url(
        config,
        transaction,
        "https://secscan.example.com/api/v1/auth/oidc/callback",
    )
    parsed = urlsplit(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://login.example.com/oauth2/authorize"
    )
    query = parse_qs(parsed.query)
    assert query == {
        "client_id": ["secscan-web"],
        "redirect_uri": ["https://secscan.example.com/api/v1/auth/oidc/callback"],
        "response_type": ["code"],
        "scope": ["openid"],
        "state": [transaction.state],
        "nonce": [transaction.nonce],
    }
    assert config.client_secret not in url


def test_authorization_url_rejects_non_https_redirect_uri(tmp_path: Path) -> None:
    config = _config()
    discovery = OidcDiscoveryDocument.from_mapping(config, _document())
    transaction = OidcLoginTransactionStore(tmp_path / "jobs.db").create()

    with pytest.raises(ValueError, match="absolute HTTPS"):
        discovery.authorization_url(
            config,
            transaction,
            "http://secscan.example.com/api/v1/auth/oidc/callback",
        )


def test_discovery_metadata_does_not_follow_unvalidated_authorization_endpoint(
    tmp_path: Path,
) -> None:
    config = _config()
    discovery = OidcDiscoveryDocument.from_mapping(
        config,
        _document(authorization_endpoint="https://idp.example.net/authorize?tenant=one"),
    )
    transaction = OidcLoginTransactionStore(tmp_path / "jobs.db").create()
    url = discovery.authorization_url(
        config,
        transaction,
        "https://secscan.example.com/api/v1/auth/oidc/callback",
    )
    parsed = urlsplit(url)
    assert parsed.hostname == "idp.example.net"
    assert parse_qs(parsed.query)["tenant"] == ["one"]
