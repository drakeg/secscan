from __future__ import annotations

import html
import os
from pathlib import Path
import sqlite3
from typing import Literal, TypedDict

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from secscan.auth import AuthStore, LoginRequest, SESSION_COOKIE, SESSION_DAYS

PlanName = Literal["free", "professional"]


class PlanDefinition(TypedDict):
    name: str
    tagline: str
    features: list[str]


PLANS: dict[str, PlanDefinition] = {
    "free": {
        "name": "Free",
        "tagline": "Evaluate secscan and cover core targets.",
        "features": [
            "Repository, image, filesystem, SBOM, and basic network scanning",
            "Normalized findings and scan history",
            "KEV/EPSS-aware prioritization when local enrichment data is configured",
            "Persistent asset inventory",
        ],
    },
    "professional": {
        "name": "Professional",
        "tagline": "Broader assessment workflows for serious security operations.",
        "features": [
            "Everything in Free",
            "Authenticated host assessment workflows",
            "Encrypted reusable SSH credential profiles",
            "Advanced asset and prioritization workflows as they are released",
            "Priority path for future integrations and team features",
        ],
    },
}


class PlanRegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)
    plan: PlanName


class PlanChangeRequest(BaseModel):
    plan: PlanName


class PlanStore:
    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        AuthStore(self.database)
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def migrate(self) -> None:
        with self._connect() as connection:
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(auth_users)").fetchall()
            }
            if "plan" not in columns:
                connection.execute(
                    "ALTER TABLE auth_users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'"
                )

    def get(self, user_id: str) -> str:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT plan FROM auth_users WHERE id = ?", (user_id,)
            ).fetchone()
        if row is None:
            raise ValueError("account was not found")
        plan = str(row["plan"])
        return plan if plan in PLANS else "free"

    def set(self, user_id: str, plan: str) -> str:
        if plan not in PLANS:
            raise ValueError("unknown plan")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE auth_users SET plan = ? WHERE id = ?", (plan, user_id)
            )
            if cursor.rowcount != 1:
                raise ValueError("account was not found")
        return plan


def _secure_cookie() -> bool:
    return os.environ.get("SECSCAN_SESSION_COOKIE_SECURE", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _registration_enabled() -> bool:
    return os.environ.get("SECSCAN_REGISTRATION_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=_secure_cookie(),
        samesite="strict",
        max_age=SESSION_DAYS * 86400,
        path="/",
    )


def _plan_cards(*, selectable: bool = False, selected: str = "free") -> str:
    cards: list[str] = []
    for key, definition in PLANS.items():
        features = "".join(
            f"<li>{html.escape(item)}</li>" for item in definition["features"]
        )
        choice = ""
        if selectable:
            checked = " checked" if key == selected else ""
            choice = (
                f"<label class='plan-choice'><input type='radio' name='plan' value='{key}'{checked}>"
                f"Choose {html.escape(definition['name'])}</label>"
            )
        cards.append(
            f"<article class='plan-card'><h3>{html.escape(definition['name'])}</h3>"
            f"<p>{html.escape(definition['tagline'])}</p><ul>{features}</ul>{choice}</article>"
        )
    return "".join(cards)


def _page_style() -> str:
    return """
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#07111f;color:#e5eef8}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#10243d 0,#07111f 45%);min-height:100vh}
    a{color:inherit}.wrap{width:min(1120px,92vw);margin:auto}nav{display:flex;align-items:center;justify-content:space-between;padding:1.2rem 0}
    .brand{font-size:1.35rem;font-weight:800}.actions{display:flex;gap:.7rem;flex-wrap:wrap}.button,button{border:1px solid #33506f;background:#10243d;color:#fff;border-radius:9px;padding:.7rem 1rem;text-decoration:none;font-weight:700;cursor:pointer}.primary{background:#2563eb;border-color:#3b82f6}
    .hero{padding:5.5rem 0 3rem;display:grid;grid-template-columns:1.2fr .8fr;gap:3rem;align-items:center}.eyebrow{text-transform:uppercase;letter-spacing:.12em;color:#7dd3fc;font-weight:800;font-size:.8rem}.hero h1{font-size:clamp(2.5rem,6vw,4.7rem);line-height:.98;margin:.5rem 0 1.2rem}.hero p{font-size:1.18rem;color:#b8c7da;line-height:1.65}
    .hero-panel,.card,.plan-card,.auth-card{background:#0d1c2f;border:1px solid #203a58;border-radius:16px;padding:1.4rem;box-shadow:0 20px 50px #0005}.hero-panel ul,.plan-card ul{padding-left:1.2rem;line-height:1.75;color:#c8d6e7}
    section{padding:2.5rem 0}.section-title{text-align:center;margin-bottom:1.7rem}.section-title h2{font-size:2rem;margin:.3rem}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.plans{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;max-width:850px;margin:auto}.plan-card h3{font-size:1.5rem;margin:.2rem 0}.plan-choice{display:block;margin-top:1rem;padding:.75rem;background:#132941;border-radius:9px;font-weight:800}.muted{color:#93a7bd}.notice{padding:.9rem 1rem;border:1px solid #7c5c20;background:#2b210d;border-radius:10px;color:#fde68a}
    .auth-shell{min-height:100vh;display:grid;place-items:center;padding:2rem}.auth-card{width:min(760px,94vw)}label{display:block;margin:1rem 0}input[type=email],input[type=password]{width:100%;padding:.8rem;border-radius:8px;border:1px solid #33506f;background:#07111f;color:#fff}#error{color:#fca5a5;min-height:1.2rem}
    footer{padding:3rem 0;color:#7890a9;text-align:center}@media(max-width:760px){.hero{grid-template-columns:1fr;padding-top:3rem}.grid,.plans{grid-template-columns:1fr}}
    """


def _landing(user_email: str | None, plan: str | None) -> str:
    authenticated = user_email is not None
    account_actions = (
        f"<a class='button' href='/account/plan'>Plan: {html.escape(PLANS[plan or 'free']['name'])}</a>"
        "<a class='button primary' href='/app'>Open workspace</a>"
        if authenticated
        else "<a class='button' href='/login'>Sign in</a><a class='button primary' href='/register'>Start free</a>"
    )
    hero_actions = (
        "<a class='button primary' href='/app'>Open workspace</a>"
        "<a class='button' href='/account/plan'>Manage plan</a>"
        if authenticated
        else "<a class='button primary' href='/register'>Create an account</a>"
        "<a class='button' href='#plans'>Compare plans</a>"
    )
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>secscan · security scanning workspace</title><style>{_page_style()}</style></head><body>
    <div class='wrap'><nav><div class='brand'>secscan</div><div class='actions'>{account_actions}</div></nav>
    <main><section class='hero'><div><p class='eyebrow'>Security scanning without the sprawl</p><h1>Find what needs fixing first.</h1><p>secscan brings repository, container, SBOM, network, Linux, and Windows assessment evidence into one browsable security workspace. Normalize findings, track assets and history, and prioritize known-exploited and high-likelihood vulnerabilities without juggling a pile of disconnected tools.</p><div class='actions'>{hero_actions}</div></div>
    <aside class='hero-panel'><p class='eyebrow'>One workspace</p><h2>Coverage built for operators</h2><ul><li>Repository and secret scanning</li><li>Container and SBOM vulnerability analysis</li><li>Network and web-facing assessment</li><li>Authenticated Linux and Windows posture collection</li><li>KEV + EPSS-aware prioritization</li><li>Persistent asset and scan history</li></ul></aside></section>
    <section><div class='section-title'><p class='eyebrow'>How it helps</p><h2>From scan output to an actionable queue</h2></div><div class='grid'><article class='card'><h3>Scan broadly</h3><p class='muted'>Use purpose-built adapters for code, images, hosts, networks, and software inventories.</p></article><article class='card'><h3>Normalize evidence</h3><p class='muted'>Keep scanner-specific output behind a consistent secscan finding and reporting model.</p></article><article class='card'><h3>Prioritize risk</h3><p class='muted'>Bring severity, CISA KEV status, and EPSS likelihood together so urgent targets rise to the top.</p></article></div></section>
    <section id='plans'><div class='section-title'><p class='eyebrow'>Plans</p><h2>Start small, expand when you need more</h2></div><div class='plans'>{_plan_cards()}</div><p class='muted' style='text-align:center;margin-top:1rem'>Professional is currently a preview access tier. Billing is not connected yet, so selecting it does not create a charge.</p></section></main><footer>secscan · security assessment evidence you can act on</footer></div></body></html>"""


def _login_page() -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Sign in · secscan</title><style>{_page_style()}</style></head><body><div class='auth-shell'><main class='auth-card'><a href='/'>← secscan</a><h1>Sign in</h1><p id='error'></p><form id='auth'><label>Email<input id='email' type='email' required autocomplete='email'></label><label>Password<input id='password' type='password' required autocomplete='current-password'></label><button class='primary' type='submit'>Sign in</button></form><p>New to secscan? <a href='/register'>Create an account</a>.</p></main></div><script>document.getElementById('auth').addEventListener('submit',async(e)=>{{e.preventDefault();const r=await fetch('/api/v1/auth/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:document.getElementById('email').value,password:document.getElementById('password').value}})}});if(r.ok){{location.href='/app';return}}const d=await r.json().catch(()=>({{}}));document.getElementById('error').textContent=d.detail||'Authentication failed';}});</script></body></html>"""


def _register_page() -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Create account · secscan</title><style>{_page_style()}</style></head><body><div class='auth-shell'><main class='auth-card'><a href='/'>← secscan</a><h1>Create your account</h1><p class='muted'>Choose the tier that fits how you want to evaluate or use secscan.</p><p class='notice'>Professional is a preview tier today. No payment method is collected and selecting it does not create a charge.</p><p id='error'></p><form id='auth'><label>Email<input id='email' type='email' required autocomplete='email'></label><label>Password<input id='password' type='password' required minlength='12' autocomplete='new-password'></label><div class='plans'>{_plan_cards(selectable=True)}</div><button class='primary' type='submit'>Create account</button></form><p>Already registered? <a href='/login'>Sign in</a>.</p></main></div><script>document.getElementById('auth').addEventListener('submit',async(e)=>{{e.preventDefault();const chosen=document.querySelector('input[name=plan]:checked');const r=await fetch('/api/v1/auth/register',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:document.getElementById('email').value,password:document.getElementById('password').value,plan:chosen.value}})}});if(r.ok){{location.href='/app';return}}const d=await r.json().catch(()=>({{}}));document.getElementById('error').textContent=d.detail||'Registration failed';}});</script></body></html>"""


def _account_page(email: str, plan: str) -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Plan · secscan</title><style>{_page_style()}</style></head><body><div class='wrap'><nav><div class='brand'><a href='/'>secscan</a></div><div class='actions'><a class='button' href='/app'>Workspace</a></div></nav><main><section><div class='section-title'><p class='eyebrow'>Account</p><h1>{html.escape(email)}</h1><p>Current plan: <strong id='current-plan'>{html.escape(PLANS[plan]['name'])}</strong></p></div><p class='notice'>Professional is a preview tier. Billing is not connected yet, so changing tiers does not create a charge.</p><div class='plans'>{_plan_cards(selectable=True, selected=plan)}</div><div style='text-align:center;margin-top:1.2rem'><button id='save-plan' class='primary'>Save plan</button><p id='status'></p></div></section></main></div><script>document.getElementById('save-plan').addEventListener('click',async()=>{{const plan=document.querySelector('input[name=plan]:checked').value;const r=await fetch('/api/v1/account/plan',{{method:'PUT',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{plan}})}});const d=await r.json().catch(()=>({{}}));if(!r.ok){{document.getElementById('status').textContent=d.detail||'Could not update plan';return}}document.getElementById('current-plan').textContent=d.plan_name;document.getElementById('status').textContent='Plan updated.';}});</script></body></html>"""


class PlanEntitlementMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, database: Path) -> None:
        super().__init__(app)
        self.auth = AuthStore(database)
        self.plans = PlanStore(database)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        restricted = request.url.path.startswith("/api/v1/ssh-credentials") or request.url.path == "/api/v1/linux-host-jobs"
        if restricted:
            user = self.auth.user_for_session(request.cookies.get(SESSION_COOKIE))
            if user is not None and self.plans.get(user.id) != "professional":
                return JSONResponse(
                    {"detail": "Professional plan is required for authenticated host workflows"},
                    status_code=403,
                )
        return await call_next(request)


def mount_public_site(app: FastAPI, *, database: Path) -> FastAPI:
    auth = AuthStore(database)
    plans = PlanStore(database)

    def session_user(request: Request):  # type: ignore[no-untyped-def]
        user = auth.user_for_session(request.cookies.get(SESSION_COOKIE))
        if user is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    @app.get("/", response_class=HTMLResponse)
    def landing(request: Request) -> str:
        user = auth.user_for_session(request.cookies.get(SESSION_COOKIE))
        return _landing(user.email if user else None, plans.get(user.id) if user else None)

    @app.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return _login_page()

    @app.get("/register", response_class=HTMLResponse)
    def register_page() -> str:
        if not _registration_enabled():
            raise HTTPException(status_code=404, detail="registration is disabled")
        return _register_page()

    @app.post("/api/v1/auth/register", status_code=201)
    def register(request: PlanRegisterRequest, response: Response) -> dict[str, object]:
        if not _registration_enabled():
            raise HTTPException(status_code=403, detail="registration is disabled")
        try:
            user = auth.register(request.email, request.password)
            plan = plans.set(user.id, request.plan)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        _set_session_cookie(response, auth.create_session(user.id))
        return user.public() | {"plan": plan, "plan_name": PLANS[plan]["name"]}

    @app.post("/api/v1/auth/login")
    def login(request: LoginRequest, response: Response) -> dict[str, object]:
        user = auth.authenticate(request.email, request.password)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid email or password")
        _set_session_cookie(response, auth.create_session(user.id))
        plan = plans.get(user.id)
        return user.public() | {"plan": plan, "plan_name": PLANS[plan]["name"]}

    @app.get("/account/plan", response_class=HTMLResponse)
    def account_plan(request: Request) -> str:
        user = session_user(request)
        return _account_page(user.email, plans.get(user.id))

    @app.get("/api/v1/account/plan")
    def get_plan(request: Request) -> dict[str, object]:
        user = session_user(request)
        plan = plans.get(user.id)
        return {"plan": plan, "plan_name": PLANS[plan]["name"], "definition": PLANS[plan]}

    @app.put("/api/v1/account/plan")
    def change_plan(request: Request, change: PlanChangeRequest) -> dict[str, object]:
        user = session_user(request)
        try:
            plan = plans.set(user.id, change.plan)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"plan": plan, "plan_name": PLANS[plan]["name"], "definition": PLANS[plan]}

    app.add_middleware(PlanEntitlementMiddleware, database=database)
    return app