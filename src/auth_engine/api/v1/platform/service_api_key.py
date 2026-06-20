import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.api.dependencies.service_api_deps import _hash_key
from auth_engine.models import UserORM
from auth_engine.models.service_api_key import ServiceApiKeyORM as KeyORM
from auth_engine.repositories.service_api_key_repo import ServiceApiKeyRepository
from auth_engine.schemas.service_api_key import (
    ApiKeyCreatorInfo,
    ApiKeyListItem,
    CreateApiKeyRequest,
    CreateApiKeyResponse,
)
from auth_engine.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter()


def _serialize_key(key: KeyORM) -> ApiKeyListItem:
    creator = (
        ApiKeyCreatorInfo.model_validate(key.creator)
        if getattr(key, "creator", None) is not None
        else None
    )
    return ApiKeyListItem(
        id=key.id,
        service_name=key.service_name,
        key_prefix=key.key_prefix,
        tenant_id=key.tenant_id,
        is_active=key.is_active,
        created_by=key.created_by,
        creator=creator,
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        created_at=key.created_at,
    )


@router.post(
    "/service-keys",
    response_model=CreateApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a service API key",
)
async def create_service_key(
    payload: CreateApiKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: UserORM = Depends(check_platform_permission("platform.tenants.manage")),
) -> CreateApiKeyResponse:
    """
    Create an API key for an external service.

    The raw key is shown ONCE in the response and never stored.
    The service must store it securely (e.g. as an environment variable).

    Key format: ae_sk_{32 random bytes in hex}
    """
    raw_key = f"ae_sk_{secrets.token_hex(32)}"
    key_prefix = raw_key[:12] + "..."
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

    await audit_service.log(
        actor_id=current_user.id,
        action="SERVICE_KEY_CREATED",
        resource="ServiceApiKey",
        resource_id=str(api_key.id),
        tenant_id=str(payload.tenant_id) if payload.tenant_id else None,
        metadata={
            "service_name": payload.service_name,
            "key_prefix": key_prefix,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    logger.info(
        f"[service-keys] Created key for service='{payload.service_name}' "
        f"by user={current_user.id}"
    )

    return CreateApiKeyResponse(
        id=api_key.id,
        service_name=api_key.service_name,
        key_prefix=api_key.key_prefix,
        tenant_id=api_key.tenant_id,
        created_by=current_user.id,
        creator=ApiKeyCreatorInfo.model_validate(current_user),
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        raw_key=raw_key,
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
    result = await db.execute(select(KeyORM).options(joinedload(KeyORM.creator)))
    keys = result.scalars().unique().all()
    return [_serialize_key(k) for k in keys]


@router.delete(
    "/service-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a service API key",
)
async def revoke_service_key(
    key_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
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

    if not key.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key is already revoked",
        )

    await repo.update(key_id, {"is_active": False})
    await db.commit()

    await audit_service.log(
        actor_id=current_user.id,
        action="SERVICE_KEY_REVOKED",
        resource="ServiceApiKey",
        resource_id=str(key_id),
        tenant_id=str(key.tenant_id) if key.tenant_id else None,
        metadata={
            "service_name": key.service_name,
            "key_prefix": key.key_prefix,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    logger.info(
        f"[service-keys] Revoked key {key_id} "
        f"(service={key.service_name}) by user={current_user.id}"
    )
