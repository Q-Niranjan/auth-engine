# api/v1/public/magic_link.py
"""
Magic Link public endpoints
===========================

POST /auth/magic-link/request
  - Accepts an email address
  - Generates a signed JWT, stores a Redis one-time flag, sends the link via email
  - Always responds 202 (prevents email enumeration)

GET  /auth/magic-link/verify?token=<jwt>
  - Validates the JWT signature, TTL, and Redis one-time flag
  - Consumes the flag (link becomes invalid immediately)
  - Issues standard AuthEngine access + refresh tokens
"""

import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
)
from auth_engine.core.redis import get_redis
from auth_engine.external_services.email.resolver import EmailServiceResolver
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository
from auth_engine.schemas.magic_link import (
    MagicLinkRequest,
    MagicLinkRequestResponse,
    MagicLinkVerifyResponse,
)
from auth_engine.services.magic_link_service import MagicLinkService

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency — build EmailServiceResolver from the current DB session
# ---------------------------------------------------------------------------


def _get_email_resolver(db: AsyncSession = Depends(get_db)) -> EmailServiceResolver:
    repo = TenantEmailConfigRepository(db)
    return EmailServiceResolver(repo)


# ---------------------------------------------------------------------------
# POST /auth/magic-link/request
# ---------------------------------------------------------------------------


@router.post(
    "/request",
    response_model=MagicLinkRequestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a magic sign-in link",
    description=(
        "Send a one-time, 15-minute magic sign-in link to the provided email address. "
        "Always returns 202 — even if the email is not registered — to prevent enumeration."
    ),
)
async def request_magic_link(
    body: MagicLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
    email_resolver: EmailServiceResolver = Depends(_get_email_resolver),
) -> MagicLinkRequestResponse:
    svc = MagicLinkService(db, redis_conn, email_resolver)
    ip = request.client.host if request.client else None

    try:
        await svc.request_magic_link(
            email=str(body.email),
            ip_address=ip,
        )
    except Exception as exc:
        # Log the real error server-side but never leak it to the caller
        logger.error(f"[MagicLink] request_magic_link error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to send the magic link email. Please try again shortly.",
        ) from exc

    return MagicLinkRequestResponse()


# ---------------------------------------------------------------------------
# GET /auth/magic-link/verify
# ---------------------------------------------------------------------------


@router.get(
    "/verify",
    response_model=MagicLinkVerifyResponse,
    summary="Verify a magic sign-in link",
    description=(
        "Exchange a valid, unused magic-link token for AuthEngine access and refresh tokens. "
        "The token is single-use — clicking the link a second time will return 401."
    ),
)
async def verify_magic_link(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
    email_resolver: EmailServiceResolver = Depends(_get_email_resolver),
) -> MagicLinkVerifyResponse:
    svc = MagicLinkService(db, redis_conn, email_resolver)
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    try:
        tokens = await svc.verify_magic_link(
            token=token,
            ip_address=ip,
            user_agent=ua,
        )
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc.message),
        ) from exc
    except (InvalidTokenError, AuthenticationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc.message),
        ) from exc
    except Exception as exc:
        logger.exception(f"[MagicLink] verify_magic_link unexpected error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Magic link verification failed. Please try again.",
        ) from exc

    return MagicLinkVerifyResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens.get("token_type", "bearer"),
        expires_in=tokens.get("expires_in", 1800),
    )
