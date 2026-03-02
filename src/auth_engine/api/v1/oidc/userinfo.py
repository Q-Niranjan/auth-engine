"""
OIDC UserInfo Endpoint

Returns standard OIDC claims for the authenticated user.
Called by OIDC clients after the authorization code flow to
fetch the user's profile using their access token.

Endpoint:
    GET  /oidc/userinfo   — standard claims (Bearer token required)
    POST /oidc/userinfo   — same, POST form is also valid per spec
"""

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from fastapi.security import HTTPAuthorizationCredentials
from auth_engine.api.dependencies.auth_deps import get_current_active_user, security
from auth_engine.core.security import token_manager
from auth_engine.models.user import UserORM

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/userinfo",
    summary="OIDC UserInfo",
    description=(
        "Returns standard OpenID Connect claims for the authenticated user. "
        "Requires a valid Bearer access token in the Authorization header. "
        "Claim names follow the OIDC Core 1.0 specification."
    ),
    tags=["oidc"],
)
@router.post("/userinfo", include_in_schema=False)  # POST is also valid per OIDC spec
async def userinfo(
    current_user: UserORM = Depends(get_current_active_user),
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> JSONResponse:
    """
    UserInfo endpoint — returns OIDC standard claims.

    Standard claims returned:
        sub           — stable unique user ID (UUID)
        email         — user's email address
        email_verified — whether the email has been verified
        name          — full display name (first + last)
        given_name    — first name
        family_name   — last name
        picture       — avatar URL (if set)
        updated_at    — last profile update timestamp (Unix epoch)

    Usage:
        GET /api/v1/oidc/userinfo
        Authorization: Bearer <access_token>
    """
    # Build full name — only include if at least one part exists
    given_name = current_user.first_name or ""
    family_name = current_user.last_name or ""
    name = f"{given_name} {family_name}".strip() or None

    # Extract pairwise `sub` created during token generation
    token = credentials.credentials
    payload = token_manager.verify_access_token(token)
    returned_sub = payload.get("oidc_sub", str(current_user.id))

    claims = {
        # ── Required OIDC claims ──────────────────────────────────────────
        "sub": returned_sub,

        # ── Profile scope claims ──────────────────────────────────────────
        "name": name,
        "given_name": given_name or None,
        "family_name": family_name or None,
        "picture": current_user.avatar_url,
        "updated_at": int(current_user.updated_at.timestamp()) if current_user.updated_at else None,

        # ── Email scope claims ────────────────────────────────────────────
        "email": str(current_user.email),
        "email_verified": current_user.is_email_verified,

        # ── AuthEngine-specific extensions (non-standard, prefixed) ───────
        "authengine:username": current_user.username,
        "authengine:phone_verified": current_user.is_phone_verified,
        "authengine:auth_strategies": current_user.auth_strategies or [],
        "authengine:mfa_enabled": current_user.mfa_enabled,
    }

    # Remove None values — cleaner response, clients shouldn't get null claims
    claims = {k: v for k, v in claims.items() if v is not None}

    return JSONResponse(
        content=claims,
        headers={"Cache-Control": "no-store"},  # userinfo must never be cached
    )