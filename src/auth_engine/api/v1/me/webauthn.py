"""
WebAuthn /me endpoints
======================

Allows an authenticated user to list and delete their registered passkeys.

GET    /me/webauthn/credentials           → list all registered passkeys
DELETE /me/webauthn/credentials/{cred_id} → remove a specific passkey
"""

import logging
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.exceptions import NotFoundError
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.schemas.webauthn import WebAuthnCredentialListResponse, WebAuthnCredentialResponse
from auth_engine.services.webauthn_service import WebAuthnService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/credentials",
    response_model=WebAuthnCredentialListResponse,
    summary="List registered passkeys",
    description="Returns all WebAuthn credentials (passkeys) registered by the current user.",
)
async def list_credentials(
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> WebAuthnCredentialListResponse:
    service = WebAuthnService(db=db, redis=redis_conn)
    creds = await service.list_credentials(current_user)

    return WebAuthnCredentialListResponse(
        credentials=[WebAuthnCredentialResponse(**c) for c in creds],
        total=len(creds),
    )


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a passkey",
    description=(
        "Deletes a specific WebAuthn credential. "
        "If this was the user's last passkey, 'webauthn' is removed from their auth_strategies."
    ),
)
async def delete_credential(
    credential_id: uuid.UUID,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> None:
    service = WebAuthnService(db=db, redis=redis_conn)
    try:
        await service.delete_credential(current_user, credential_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    logger.info(f"[webauthn] credential deleted user={current_user.id} cred={credential_id}")
