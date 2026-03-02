"""
WebAuthn Public Endpoints
=========================

Registration ceremony  →  POST /auth/webauthn/register/begin
                           POST /auth/webauthn/register/complete

Authentication ceremony →  POST /auth/webauthn/authenticate/begin
                           POST /auth/webauthn/authenticate/complete

These endpoints are public (no auth required for authenticate; auth required
for register because a user must already be logged in to attach a passkey).
"""

import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.exceptions import AuthenticationError, NotFoundError
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.schemas.user import UserLoginResponse
from auth_engine.schemas.webauthn import (
    WebAuthnAuthBeginRequest,
    WebAuthnAuthBeginResponse,
    WebAuthnAuthCompleteRequest,
    WebAuthnRegisterBeginResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
)
from auth_engine.services.webauthn_service import WebAuthnService

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Registration ──────────────────────────────────────────────────────────────


@router.post(
    "/register/begin",
    response_model=WebAuthnRegisterBeginResponse,
    summary="Begin passkey registration",
    description=(
        "Generates a WebAuthn PublicKeyCredentialCreationOptions challenge. "
        "Pass the returned `options` to `navigator.credentials.create()` in the browser. "
        "Requires an authenticated session — the passkey is attached to the current user."
    ),
)
async def register_begin(
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> WebAuthnRegisterBeginResponse:
    service = WebAuthnService(db=db, redis=redis_conn)
    try:
        options = await service.begin_registration(current_user)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    logger.info(f"[webauthn] register/begin user={current_user.id}")
    return WebAuthnRegisterBeginResponse(options=options)


@router.post(
    "/register/complete",
    response_model=WebAuthnRegisterCompleteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Complete passkey registration",
    description=(
        "Verifies the attestation response from `navigator.credentials.create()` "
        "and persists the new passkey. The `device_name` field lets users label "
        "their authenticators (e.g. 'MacBook Touch ID', 'YubiKey 5C')."
    ),
)
async def register_complete(
    body: WebAuthnRegisterCompleteRequest,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> WebAuthnRegisterCompleteResponse:
    service = WebAuthnService(db=db, redis=redis_conn)
    try:
        result = await service.complete_registration(
            user=current_user,
            credential_json=body.credential,
            device_name=body.device_name,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    logger.info(f"[webauthn] register/complete user={current_user.id} device='{body.device_name}'")
    return WebAuthnRegisterCompleteResponse(
        credential_id=result["credential_id"],
        device_name=result["device_name"],
    )


# ── Authentication ────────────────────────────────────────────────────────────


@router.post(
    "/authenticate/begin",
    response_model=WebAuthnAuthBeginResponse,
    summary="Begin passkey authentication",
    description=(
        "Generates a WebAuthn PublicKeyCredentialRequestOptions challenge. "
        "Supply `email` to get credentials scoped to that user (targeted assertion). "
        "Omit `email` for a discoverable-credential (resident-key) flow where the "
        "authenticator picks the account. "
        "Pass the returned `options` to `navigator.credentials.get()`."
    ),
)
async def authenticate_begin(
    body: WebAuthnAuthBeginRequest,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> WebAuthnAuthBeginResponse:
    service = WebAuthnService(db=db, redis=redis_conn)
    try:
        options = await service.begin_authentication(email=body.email)
    except Exception as exc:
        logger.error(f"[webauthn] authenticate/begin error: {exc}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return WebAuthnAuthBeginResponse(options=options)


@router.post(
    "/authenticate/complete",
    response_model=UserLoginResponse,
    summary="Complete passkey authentication",
    description=(
        "Verifies the assertion response from `navigator.credentials.get()`, "
        "updates the sign counter, and issues a full session (access + refresh tokens). "
        "This is the passwordless login completion step."
    ),
)
async def authenticate_complete(
    body: WebAuthnAuthCompleteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> UserLoginResponse:
    service = WebAuthnService(db=db, redis=redis_conn)

    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    try:
        tokens = await service.complete_authentication(
            credential_json=body.credential,
            ip_address=ip,
            user_agent=ua,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except Exception as exc:
        logger.error(f"[webauthn] authenticate/complete unexpected error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed",
        )

    logger.info("[webauthn] authenticate/complete — session issued")
    return UserLoginResponse(**tokens)