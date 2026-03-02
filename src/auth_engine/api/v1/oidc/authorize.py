"""
OIDC Authorization Endpoint

The entry point for "Login with AuthEngine" flows.
When a user clicks "Login with AuthEngine" on YourApp, YourApp
redirects the browser here. AuthEngine handles login, then redirects
back to YourApp with an authorization code.

Endpoint:
    GET /oidc/authorize

Flow:
    YourApp → GET /oidc/authorize?client_id=yourapp&redirect_uri=...&scope=openid
    AuthEngine → shows login page (or reuses existing session)
    User logs in
    AuthEngine → 302 to redirect_uri?code=<code>&state=<state>
    YourApp backend → POST /oidc/token to exchange code for tokens
"""

import json
import logging
import secrets
import time
from typing import Annotated
from urllib.parse import urlencode

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from auth_engine.api.dependencies.auth_deps import get_current_user_optional
from auth_engine.core.config import settings
from auth_engine.core.redis import get_redis
from auth_engine.core.templates import jinja_env
from auth_engine.models.user import UserORM

logger = logging.getLogger(__name__)
router = APIRouter()

# Authorization codes expire in 10 minutes (OIDC spec: MUST NOT exceed 10 min)
AUTH_CODE_TTL = 600


# ── Template helpers ─────────────────────────────────────────────────────────


def _render_login(
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    nonce: str,
    code_challenge: str,
    code_challenge_method: str,
    authorize_url: str,
    error: str | None = None,
) -> str:
    tmpl = jinja_env.get_template("oidc/login.html")
    return tmpl.render(
        app_name=settings.APP_NAME,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        scopes=scope.split(),
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        authorize_url=authorize_url,
        error=error,
    )


def _render_error(message: str) -> str:
    tmpl = jinja_env.get_template("oidc/error.html")
    return tmpl.render(app_name=settings.APP_NAME, message=message)


# ── Authorization endpoint ────────────────────────────────────────────────────


@router.get(
    "/authorize",
    response_model=None,
    summary="OIDC Authorization Endpoint",
    description=(
        "Entry point for 'Login with AuthEngine' flows. "
        "Validates the authorization request, checks for an existing session, "
        "and either issues a code immediately or shows the login page. "
        "Supports PKCE (S256) for public/mobile clients."
    ),
)
async def authorize(
    request: Request,
    response_type: Annotated[str, Query(description="Must be 'code'")] = "code",
    client_id: Annotated[str, Query(description="Your app's client identifier")] = "",
    redirect_uri: Annotated[str, Query(description="Where to send the user after login")] = "",
    scope: Annotated[
        str, Query(description="Space-separated scopes: openid profile email")
    ] = "openid",
    state: Annotated[str | None, Query(description="CSRF state — echoed back in redirect")] = None,
    nonce: Annotated[str | None, Query(description="Replay protection for id_token")] = None,
    code_challenge: Annotated[str | None, Query(description="PKCE S256 code challenge")] = None,
    code_challenge_method: Annotated[str | None, Query(description="Must be S256")] = None,
    current_user: UserORM | None = Depends(get_current_user_optional),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> HTMLResponse | RedirectResponse:
    """
    OIDC Authorization endpoint.

    If the user already has a valid Bearer token → issue code immediately.
    Otherwise → serve the login page.
    """

    # ── Validate required params ──────────────────────────────────────────
    errors: list[str] = []
    if response_type != "code":
        errors.append(f"response_type '{response_type}' is not supported — use 'code'")
    if not client_id:
        errors.append("client_id is required")
    if not redirect_uri:
        errors.append("redirect_uri is required")
    if "openid" not in scope.split():
        errors.append("scope must include 'openid'")
    if code_challenge_method and code_challenge_method != "S256":
        errors.append("only code_challenge_method=S256 is supported")

    if errors:
        return HTMLResponse(content=_render_error("\n".join(errors)), status_code=400)

    # ── If already authenticated, skip login and issue code immediately ───
    if current_user is not None:
        code = await _issue_authorization_code(
            redis_conn=redis_conn,
            user_id=str(current_user.id),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
        )
        logger.info(f"[oidc/authorize] Silent SSO for user={current_user.id} client={client_id}")
        return _redirect_with_code(redirect_uri, code, state)

    # ── Unauthenticated — show login page ─────────────────────────────────
    return HTMLResponse(
        content=_render_login(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state or "",
            nonce=nonce or "",
            code_challenge=code_challenge or "",
            code_challenge_method=code_challenge_method or "",
            authorize_url=f"{settings.API_V1_PREFIX}/oidc/authorize/submit",
        ),
        status_code=200,
    )


# ── Login form submission ─────────────────────────────────────────────────────


@router.post(
    "/authorize/submit",
    response_model=None,
    summary="OIDC Login Form Submission",
    description="Internal — handles credential submission from the OIDC login page.",
    include_in_schema=False,
)
async def authorize_submit(
    request: Request,
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> HTMLResponse | RedirectResponse:
    """
    Validates credentials from the login form.
    On success: issues an authorization code and redirects to redirect_uri.
    On failure: re-renders the login page with an error message.
    """
    from auth_engine.api.dependencies.deps import get_db
    from auth_engine.core.security import security as crypto
    from auth_engine.models.user import UserStatus
    from auth_engine.repositories.user_repo import UserRepository

    form = await request.form()

    email = str(form.get("email", ""))
    password = str(form.get("password", ""))
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    scope = str(form.get("scope", "openid"))
    state = str(form.get("state", ""))
    nonce = str(form.get("nonce", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", ""))

    def show_error(msg: str) -> HTMLResponse:
        return HTMLResponse(
            content=_render_login(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                authorize_url=f"{settings.API_V1_PREFIX}/oidc/authorize/submit",
                error=msg,
            ),
            status_code=200,
        )

    if not email or not password:
        return show_error("Email and password are required.")

    try:
        async for db in get_db():
            user_repo = UserRepository(db)
            user = await user_repo.get_by_email(email)

            if not user or not user.password_hash:
                return show_error("Invalid email or password.")

            if not crypto.verify_password(password, str(user.password_hash)):
                return show_error("Invalid email or password.")

            if user.status != UserStatus.ACTIVE:
                return show_error(f"Account is {user.status.value}. Please contact support.")

            code = await _issue_authorization_code(
                redis_conn=redis_conn,
                user_id=str(user.id),
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                nonce=nonce or None,
                code_challenge=code_challenge or None,
            )

            logger.info(f"[oidc/authorize] Code issued: user={user.id} client={client_id}")
            return _redirect_with_code(redirect_uri, code, state or None)

    except Exception as exc:
        logger.exception(f"[oidc/authorize/submit] Unexpected error: {exc}")
        return show_error("An unexpected error occurred. Please try again.")

    return show_error("Internal server error")


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _issue_authorization_code(
    *,
    redis_conn: aioredis.Redis,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    nonce: str | None,
    code_challenge: str | None,
) -> str:
    """Generate a single-use authorization code stored in Redis (TTL = 10 min)."""
    code = secrets.token_urlsafe(32)
    payload = {
        "user_id": user_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "issued_at": time.time(),
    }
    await redis_conn.setex(f"oidc:code:{code}", AUTH_CODE_TTL, json.dumps(payload))
    return code


def _redirect_with_code(redirect_uri: str, code: str, state: str | None) -> RedirectResponse:
    """Redirect back to client with ?code= (and ?state= if provided)."""
    params: dict[str, str] = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{sep}{urlencode(params)}",
        status_code=302,
    )
