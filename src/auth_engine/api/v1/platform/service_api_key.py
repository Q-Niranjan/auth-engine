import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.api.dependencies.service_api_deps import _hash_key
from auth_engine.models import UserORM
from auth_engine.repositories.service_api_key_repo import ServiceApiKeyRepository
from auth_engine.schemas.service_api_key import (
    ApiKeyListItem,
    CreateApiKeyRequest,
    CreateApiKeyResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()

router = APIRouter()


@router.post(
    "/service-keys",
    response_model=CreateApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a service API key",
)
async def create_service_key(
    payload: CreateApiKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> CreateApiKeyResponse:
    """
    Create an API key for an external service.

    The raw key is shown ONCE in the response and never stored.
    The service must store it securely (e.g. as an environment variable).

    Key format: ae_sk_{32 random bytes in hex}
    """
    # Generate raw key
    raw_key = f"ae_sk_{secrets.token_hex(32)}"
    key_prefix = raw_key[:12] + "..."  # e.g. "ae_sk_a1b2c3..."
    key_hash = _hash_key(raw_key)

    repo = ServiceApiKeyRepository(db)
    api_key = await repo.create(
        {
            "id": uuid.uuid4(),
            "service_name": payload.service_name,
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "tenant_id": payload.tenant_id,
            "is_active": True,
            "created_by": current_user.id,
            "expires_at": payload.expires_at,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
    )
    await db.commit()

    logger.info(
        f"[service-keys] Created key for service='{payload.service_name}' "
        f"by user={current_user.id}"
    )

    return CreateApiKeyResponse(
        id=api_key.id,
        service_name=api_key.service_name,
        key_prefix=api_key.key_prefix,
        tenant_id=api_key.tenant_id,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        raw_key=raw_key,  # shown ONCE — never stored
    )


@router.get(
    "/service-keys",
    response_model=list[ApiKeyListItem],
    summary="List all service API keys",
)
async def list_service_keys(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> list[ApiKeyListItem]:
    """List all service API keys. Raw keys are never shown again — only prefix."""
    from sqlalchemy import select

    from auth_engine.models.service_api_key import ServiceApiKeyORM as KeyORM

    result = await db.execute(select(KeyORM))
    keys = result.scalars().all()
    return [ApiKeyListItem.model_validate(k) for k in keys]


@router.delete(
    "/service-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a service API key",
)
async def revoke_service_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> None:
    """
    Revoke (deactivate) a service API key immediately.
    The service using it will get 401 on its next introspect call.
    """
    repo = ServiceApiKeyRepository(db)
    key = await repo.get(key_id)

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    await repo.update(key_id, {"is_active": False})
    await db.commit()

    logger.info(
        f"[service-keys] Revoked key {key_id} "
        f"(service={key.service_name}) by user={current_user.id}"
    )
