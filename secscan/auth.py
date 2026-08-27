from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import html
import os
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Any, Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

SESSION_COOKIE = "secscan_session"
SESSION_DAYS = 7
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PUBLIC_PATHS = {"/healthz", "/login", "/register", "/api/v1/auth/login", "/api/v1/auth/register"}
_PUBLIC_PREFIXES = ("/styles.css", "/dashboard.css", "/delete_scans.css", "/network.css", "/app.js", "/dashboard.js", "/linux_host.js", "/ssh_credentials.js", "/delete_scans.js")


@dataclass(frozen=True)
class User:
    id: str
    email: str
    role: str
    enabled: bool
    created_at: str

    def public(self) -> dict[str, object]:
        return {"id": self.id, "email": self.email, "role": self.role, "enabled": self.enabled, "created_at": self.created_at}


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class AuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id);
                CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
                """
            )

    def register(self, email: str, password: str) -> User:
        normalized = normalize_email(email)
        password_hash = hash_password(password)
        user_id = str(uuid4())
        created_at = _now().isoformat()
        with self._connect() as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0])
            role = "admin" if count == 0 else "user"
            try:
                connection.execute(
                    "INSERT INTO auth_users (id, email, password_hash, role, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                    (user_id, normalized, password_hash, role, created_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("an account with that email already exists") from exc
        return User(user_id, normalized, role, True, created_at)

    def authenticate(self, email: str, password: str) -> User | None:
        try:
            normalized = normalize_email(email)
        except ValueError:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM auth_users WHERE email = ?", (normalized,)).fetchone()
        if row is None or not bool(row["enabled"]) or not verify_password(password, str(row["password_hash"])):
            return None
        return _user(row)

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(48)
        created = _now()
        expires = created + timedelta(days=SESSION_DAYS)
        with self._connect() as connection:
            connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (created.isoformat(),))
            connection.execute(
                "INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (_token_hash(token), user_id, created.isoformat(), expires.isoformat()),
            )
        return token

    def user_for_session(self, token: str | None) -> User | None:
        if not token:
            return None
        now = _now().isoformat()
        with self._connect() as connection:
            row = connection.execute(
                """SELECT u.* FROM auth_sessions s JOIN auth_users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ? AND u.enabled = 1""",
                (_token_hash(token), now),
            ).fetchone()
        return _user(row) if row else None

    def revoke_session(self, token: str | None) -> None:
        if not token:
            return
        with self._connect() as connection:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_token_hash(token),))

    def list_users(self) -> list[User]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM auth_users ORDER BY created_at ASC").fetchall()
        return [_user(row) for row in rows]


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
        raise ValueError("enter a valid email address")
    return email


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        derived = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False


def _now() -> datetime:
    return datetime.now(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user(row: sqlite3.Row) -> User:
    return User(str(row["id"]), str(row["email"]), str(row["role"]), bool(row["enabled"]), str(row["created_at"]))


def _auth_page(mode: str, error: str = "") -> str:
    register = mode == "register"
    title = "Create account" if register else "Sign in"
    endpoint = "/api/v1/auth/register" if register else "/api/v1/auth/login"
    switch = '<a href="/login">Already have an account? Sign in</a>' if register else '<a href="/register">Create an account</a>'
    safe_error = html.escape(error)
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title} · secscan</title><style>body{{font-family:system-ui;background:#111827;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;margin:0}}main{{width:min(420px,90vw);background:#1f2937;padding:2rem;border-radius:14px}}label{{display:block;margin:1rem 0}}input{{box-sizing:border-box;width:100%;padding:.8rem;margin-top:.35rem}}button{{width:100%;padding:.8rem;font-weight:700}}a{{color:#93c5fd}}#error{{color:#fca5a5;min-height:1.3em}}</style></head><body><main><h1>secscan</h1><h2>{title}</h2><p id='error'>{safe_error}</p><form id='auth'><label>Email<input id='email' type='email' required autocomplete='email'></label><label>Password<input id='password' type='password' required minlength='12' autocomplete='current-password'></label><button type='submit'>{title}</button></form><p>{switch}</p></main><script>document.getElementById('auth').addEventListener('submit',async(e)=>{{e.preventDefault();const r=await fetch('{endpoint}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:document.getElementById('email').value,password:document.getElementById('password').value}})}});if(r.ok){{location.href='/';return;}}let d=await r.json().catch(()=>({{}}));document.getElementById('error').textContent=d.detail||'Authentication failed';}});</script></body></html>"""


class SessionAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, store: AuthStore, api_token: str | None) -> None:
        super().__init__(app)
        self.store = store
        self.api_token = api_token

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES) or path.startswith("/docs") or path.startswith("/openapi.json"):
            return await call_next(request)
        authorization = request.headers.get("authorization", "")
        if self.api_token and authorization.startswith("Bearer ") and secrets.compare_digest(authorization[7:], self.api_token):
            return await call_next(request)
        user = self.store.user_for_session(request.cookies.get(SESSION_COOKIE))
        if user is None:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.secscan_user = user
        if self.api_token:
            headers = list(request.scope["headers"])
            headers = [(key, value) for key, value in headers if key.lower() != b"authorization"]
            headers.append((b"authorization", f"Bearer {self.api_token}".encode()))
            request.scope["headers"] = headers
        return await call_next(request)


def mount_auth(app: FastAPI, *, database: Path, api_token: str | None = None) -> FastAPI:
    store = AuthStore(database)
    registration_enabled = os.environ.get("SECSCAN_REGISTRATION_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    secure_cookie = os.environ.get("SECSCAN_SESSION_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}

    def current_user(request: Request) -> User:
        user = store.user_for_session(request.cookies.get(SESSION_COOKIE))
        if user is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    @app.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return _auth_page("login")

    @app.get("/register", response_class=HTMLResponse)
    def register_page() -> str:
        if not registration_enabled:
            raise HTTPException(status_code=404, detail="registration is disabled")
        return _auth_page("register")

    @app.post("/api/v1/auth/register", status_code=201)
    def register(request: RegisterRequest, response: Response) -> dict[str, object]:
        if not registration_enabled:
            raise HTTPException(status_code=403, detail="registration is disabled")
        try:
            user = store.register(request.email, request.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        token = store.create_session(user.id)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=secure_cookie, samesite="strict", max_age=SESSION_DAYS * 86400, path="/")
        return user.public()

    @app.post("/api/v1/auth/login")
    def login(request: LoginRequest, response: Response) -> dict[str, object]:
        user = store.authenticate(request.email, request.password)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid email or password")
        token = store.create_session(user.id)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=secure_cookie, samesite="strict", max_age=SESSION_DAYS * 86400, path="/")
        return user.public()

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(request: Request, response: Response) -> Response:
        store.revoke_session(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.status_code = 204
        return response

    @app.get("/api/v1/auth/me")
    def me(request: Request) -> dict[str, object]:
        return current_user(request).public()

    @app.get("/api/v1/admin/users")
    def admin_users(request: Request) -> list[dict[str, object]]:
        user = current_user(request)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="administrator access required")
        return [item.public() for item in store.list_users()]

    app.add_middleware(SessionAuthMiddleware, store=store, api_token=api_token)
    return app
