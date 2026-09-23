from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class OidcProviderConfig:
    issuer: str
    client_id: str
    client_secret: str

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        allow_insecure_localhost: bool = False,
    ) -> OidcProviderConfig | None:
        source = os.environ if environment is None else environment
        issuer = source.get("SECSCAN_OIDC_ISSUER", "").strip()
        client_id = source.get("SECSCAN_OIDC_CLIENT_ID", "").strip()
        client_secret = source.get("SECSCAN_OIDC_CLIENT_SECRET", "")

        if not issuer and not client_id and not client_secret:
            return None

        missing = [
            name
            for name, value in (
                ("SECSCAN_OIDC_ISSUER", issuer),
                ("SECSCAN_OIDC_CLIENT_ID", client_id),
                ("SECSCAN_OIDC_CLIENT_SECRET", client_secret),
            )
            if not value
        ]
        if missing:
            raise ValueError("OIDC configuration is incomplete; missing " + ", ".join(missing))

        if len(client_id) > 512:
            raise ValueError("SECSCAN_OIDC_CLIENT_ID must not exceed 512 characters")
        if len(client_secret) > 4096:
            raise ValueError("SECSCAN_OIDC_CLIENT_SECRET must not exceed 4096 characters")

        return cls(
            issuer=normalize_oidc_issuer(
                issuer,
                allow_insecure_localhost=allow_insecure_localhost,
            ),
            client_id=client_id,
            client_secret=client_secret,
        )

    def public(self) -> dict[str, object]:
        return {
            "configured": True,
            "issuer": self.issuer,
            "client_id": self.client_id,
        }




@dataclass(frozen=True)
class OidcDiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    id_token_signing_alg_values_supported: tuple[str, ...]

    @classmethod
    def from_mapping(
        cls,
        config: OidcProviderConfig,
        document: Mapping[str, object],
        *,
        allow_insecure_localhost: bool = False,
    ) -> OidcDiscoveryDocument:
        issuer = _required_string(document, "issuer")
        if issuer != config.issuer:
            raise ValueError("OIDC discovery issuer does not match configured issuer")

        authorization_endpoint = _validate_oidc_endpoint(
            _required_string(document, "authorization_endpoint"),
            "authorization_endpoint",
            allow_insecure_localhost=allow_insecure_localhost,
        )
        token_endpoint = _validate_oidc_endpoint(
            _required_string(document, "token_endpoint"),
            "token_endpoint",
            allow_insecure_localhost=allow_insecure_localhost,
        )
        jwks_uri = _validate_oidc_endpoint(
            _required_string(document, "jwks_uri"),
            "jwks_uri",
            allow_insecure_localhost=allow_insecure_localhost,
        )

        response_types = _required_string_sequence(document, "response_types_supported")
        if "code" not in response_types:
            raise ValueError("OIDC provider must support authorization code flow")

        algorithms = _required_string_sequence(
            document,
            "id_token_signing_alg_values_supported",
        )
        if "none" in algorithms:
            algorithms = tuple(value for value in algorithms if value != "none")
        if not algorithms:
            raise ValueError("OIDC provider must advertise a signed ID-token algorithm")

        return cls(
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            id_token_signing_alg_values_supported=algorithms,
        )

    def authorization_url(
        self,
        config: OidcProviderConfig,
        transaction: OidcLoginTransaction,
        redirect_uri: str,
    ) -> str:
        if self.issuer != config.issuer:
            raise ValueError("OIDC discovery issuer does not match configured issuer")
        validated_redirect = _validate_redirect_uri(redirect_uri)
        query = urlencode(
            {
                "client_id": config.client_id,
                "redirect_uri": validated_redirect,
                "response_type": "code",
                "scope": "openid",
                "state": transaction.state,
                "nonce": transaction.nonce,
            }
        )
        separator = "&" if urlsplit(self.authorization_endpoint).query else "?"
        return f"{self.authorization_endpoint}{separator}{query}"


def _required_string(document: Mapping[str, object], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"OIDC discovery field {name} is required")
    return value


def _required_string_sequence(document: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = document.get(name)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"OIDC discovery field {name} is required")
    items = tuple(value)
    if not items or any(not isinstance(item, str) or not item for item in items):
        raise ValueError(f"OIDC discovery field {name} is required")
    return tuple(item for item in items if isinstance(item, str))


def _validate_oidc_endpoint(
    value: str,
    field: str,
    *,
    allow_insecure_localhost: bool,
) -> str:
    if len(value) > 4096:
        raise ValueError(f"OIDC discovery field {field} is invalid")
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError(f"OIDC discovery field {field} is invalid")
    if parsed.fragment:
        raise ValueError(f"OIDC discovery field {field} is invalid")
    local_http_allowed = (
        allow_insecure_localhost
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if parsed.scheme != "https" and not local_http_allowed:
        raise ValueError(f"OIDC discovery field {field} must use HTTPS")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"OIDC discovery field {field} is invalid") from exc
    return value


def _validate_redirect_uri(value: str) -> str:
    if not value or len(value) > 4096:
        raise ValueError("OIDC redirect URI is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("OIDC redirect URI must be an absolute HTTPS URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))




OIDC_DISCOVERY_MAX_BYTES = 256 * 1024
OIDC_DISCOVERY_TIMEOUT_SECONDS = 5.0


def oidc_discovery_url(issuer: str) -> str:
    validated = normalize_oidc_issuer(issuer)
    parsed = urlsplit(validated)
    suffix = parsed.path if parsed.path not in {"", "/"} else ""
    path = "/.well-known/openid-configuration" + suffix
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class _NoOidcRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _fetch_oidc_json(url: str, max_bytes: int, timeout: float) -> tuple[str, bytes]:
    opener = build_opener(_NoOidcRedirects())
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "secscan-oidc-discovery/1",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url != url:
                raise ValueError("OIDC discovery redirects are not allowed")
            content_type = response.headers.get("Content-Type", "")
            length_header = response.headers.get("Content-Length")
            if length_header:
                try:
                    declared_length = int(length_header)
                except ValueError as exc:
                    raise ValueError("OIDC discovery response has invalid Content-Length") from exc
                if declared_length < 0 or declared_length > max_bytes:
                    raise ValueError("OIDC discovery response exceeds size limit")
            body = response.read(max_bytes + 1)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("OIDC discovery redirects are not allowed") from exc
        raise ValueError(f"OIDC discovery request failed with HTTP {exc.code}") from exc
    except URLError as exc:
        raise ValueError("OIDC discovery request failed") from exc
    if len(body) > max_bytes:
        raise ValueError("OIDC discovery response exceeds size limit")
    return content_type, body


def fetch_oidc_discovery(
    config: OidcProviderConfig,
    *,
    fetcher: Callable[[str, int, float], tuple[str, bytes]] | None = None,
    allow_insecure_localhost: bool = False,
) -> OidcDiscoveryDocument:
    url = oidc_discovery_url(config.issuer)
    fetch = _fetch_oidc_json if fetcher is None else fetcher
    content_type, body = fetch(
        url,
        OIDC_DISCOVERY_MAX_BYTES,
        OIDC_DISCOVERY_TIMEOUT_SECONDS,
    )
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not (
        media_type.startswith("application/") and media_type.endswith("+json")
    ):
        raise ValueError("OIDC discovery response must be JSON")
    if len(body) > OIDC_DISCOVERY_MAX_BYTES:
        raise ValueError("OIDC discovery response exceeds size limit")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("OIDC discovery response is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("OIDC discovery response must be a JSON object")
    document = {str(key): value for key, value in decoded.items()}
    return OidcDiscoveryDocument.from_mapping(
        config,
        document,
        allow_insecure_localhost=allow_insecure_localhost,
    )


@dataclass(frozen=True)
class ExternalIdentity:
    issuer: str
    subject: str
    user_id: str
    linked_at: str

    def public(self) -> dict[str, str]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "user_id": self.user_id,
            "linked_at": self.linked_at,
        }


def normalize_oidc_issuer(value: str, *, allow_insecure_localhost: bool = False) -> str:
    issuer = value.strip()
    if not issuer:
        raise ValueError("OIDC issuer is required")
    if len(issuer) > 2048:
        raise ValueError("OIDC issuer must not exceed 2048 characters")

    parsed = urlsplit(issuer)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("OIDC issuer must not contain user information")
    if parsed.query or parsed.fragment:
        raise ValueError("OIDC issuer must not contain a query or fragment")
    if not parsed.hostname:
        raise ValueError("OIDC issuer must be an absolute URL")

    local_http_allowed = (
        allow_insecure_localhost
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if parsed.scheme != "https" and not local_http_allowed:
        raise ValueError("OIDC issuer must use HTTPS")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OIDC issuer port is invalid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("OIDC issuer port is invalid")

    return issuer


def _validate_subject(subject: str) -> str:
    if not subject:
        raise ValueError("OIDC subject is required")
    if len(subject) > 1024:
        raise ValueError("OIDC subject must not exceed 1024 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in subject):
        raise ValueError("OIDC subject must not contain control characters")
    return subject


class ExternalIdentityStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_external_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (issuer, subject),
                    UNIQUE (user_id, issuer)
                );
                CREATE INDEX IF NOT EXISTS auth_external_identities_user_idx
                    ON auth_external_identities(user_id);
                """
            )

    def link(self, *, issuer: str, subject: str, user_id: str) -> ExternalIdentity:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        now = datetime.now(UTC).isoformat()

        with self._connect() as connection:
            user = connection.execute(
                "SELECT 1 FROM auth_users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if user is None:
                raise ValueError("local user was not found")

            existing = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE issuer = ? AND subject = ?
                """,
                (normalized_issuer, validated_subject),
            ).fetchone()
            if existing is not None:
                if str(existing["user_id"]) != user_id:
                    raise ValueError("external identity is already linked")
                return _identity(existing)

            existing_user = connection.execute(
                """
                SELECT 1 FROM auth_external_identities
                WHERE issuer = ? AND user_id = ?
                """,
                (normalized_issuer, user_id),
            ).fetchone()
            if existing_user is not None:
                raise ValueError("local user is already linked to this OIDC issuer")

            connection.execute(
                """
                INSERT INTO auth_external_identities (issuer, subject, user_id, linked_at)
                VALUES (?, ?, ?, ?)
                """,
                (normalized_issuer, validated_subject, user_id, now),
            )

        identity = self.resolve(normalized_issuer, validated_subject)
        assert identity is not None
        return identity

    def resolve(self, issuer: str, subject: str) -> ExternalIdentity | None:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE issuer = ? AND subject = ?
                """,
                (normalized_issuer, validated_subject),
            ).fetchone()
        return _identity(row) if row is not None else None

    def list_for_user(self, user_id: str) -> list[ExternalIdentity]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT issuer, subject, user_id, linked_at
                FROM auth_external_identities
                WHERE user_id = ?
                ORDER BY issuer, subject
                """,
                (user_id,),
            ).fetchall()
        return [_identity(row) for row in rows]

    def unlink(self, *, issuer: str, subject: str, user_id: str) -> bool:
        normalized_issuer = normalize_oidc_issuer(issuer)
        validated_subject = _validate_subject(subject)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM auth_external_identities
                WHERE issuer = ? AND subject = ? AND user_id = ?
                """,
                (normalized_issuer, validated_subject, user_id),
            )
        return cursor.rowcount == 1


def _identity(row: sqlite3.Row) -> ExternalIdentity:
    return ExternalIdentity(
        issuer=str(row["issuer"]),
        subject=str(row["subject"]),
        user_id=str(row["user_id"]),
        linked_at=str(row["linked_at"]),
    )


OIDC_LOGIN_TRANSACTION_MINUTES = 10


@dataclass(frozen=True)
class OidcLoginTransaction:
    state: str
    nonce: str
    expires_at: str


@dataclass(frozen=True)
class ConsumedOidcLoginTransaction:
    nonce_digest: str
    created_at: str
    expires_at: str

    def matches_nonce(self, nonce: str) -> bool:
        candidate = _opaque_digest(_validate_opaque_value(nonce, "OIDC nonce"))
        return hmac.compare_digest(self.nonce_digest, candidate)


def _opaque_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_opaque_value(value: str, label: str) -> str:
    if not value or len(value) > 1024:
        raise ValueError(f"{label} is invalid")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ValueError(f"{label} is invalid")
    return value


class OidcLoginTransactionStore:
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
                CREATE TABLE IF NOT EXISTS auth_oidc_login_transactions (
                    state_digest TEXT PRIMARY KEY,
                    nonce_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS auth_oidc_login_transactions_expiry_idx
                    ON auth_oidc_login_transactions(expires_at);
                """
            )

    def create(self, *, now: datetime | None = None) -> OidcLoginTransaction:
        created = _utc(now)
        expires = created + timedelta(minutes=OIDC_LOGIN_TRANSACTION_MINUTES)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        state_digest = _opaque_digest(state)
        nonce_digest = _opaque_digest(nonce)

        with self._connect() as connection:
            connection.execute(
                "DELETE FROM auth_oidc_login_transactions WHERE expires_at <= ?",
                (created.isoformat(),),
            )
            connection.execute(
                """
                INSERT INTO auth_oidc_login_transactions
                    (state_digest, nonce_digest, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    state_digest,
                    nonce_digest,
                    created.isoformat(),
                    expires.isoformat(),
                ),
            )
        return OidcLoginTransaction(
            state=state,
            nonce=nonce,
            expires_at=expires.isoformat(),
        )

    def consume(
        self,
        state: str,
        *,
        now: datetime | None = None,
    ) -> ConsumedOidcLoginTransaction:
        validated_state = _validate_opaque_value(state, "OIDC state")
        state_digest = _opaque_digest(validated_state)
        current = _utc(now)

        expired = False
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT nonce_digest, created_at, expires_at
                FROM auth_oidc_login_transactions
                WHERE state_digest = ?
                """,
                (state_digest,),
            ).fetchone()
            if row is None:
                raise ValueError("OIDC login transaction is invalid or expired")

            connection.execute(
                "DELETE FROM auth_oidc_login_transactions WHERE state_digest = ?",
                (state_digest,),
            )
            expires_at = datetime.fromisoformat(str(row["expires_at"]))
            expired = expires_at <= current

        if expired:
            raise ValueError("OIDC login transaction is invalid or expired")

        return ConsumedOidcLoginTransaction(
            nonce_digest=str(row["nonce_digest"]),
            created_at=str(row["created_at"]),
            expires_at=str(row["expires_at"]),
        )


def _utc(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        raise ValueError("OIDC transaction time must be timezone-aware")
    return current.astimezone(UTC)
