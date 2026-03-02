"""
Tenant SMS Config endpoints.

GET    /tenants/{tenant_id}/sms-config
POST   /tenants/{tenant_id}/sms-config
PUT    /tenants/{tenant_id}/sms-config
DELETE /tenants/{tenant_id}/sms-config
POST   /tenants/{tenant_id}/sms-config/test

Models, repositories, resolvers and factories ALREADY EXIST.
Only the API endpoint layer is new.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.config import settings
from auth_engine.core.security import SecurityUtils
from auth_engine.external_services.sms.resolver import SMSServiceResolver
from auth_engine.models import UserORM
from auth_engine.models.sms_config import SMSProviderType as ModelSMSProviderType
from auth_engine.models.sms_config import TenantSMSConfigORM
from auth_engine.repositories.sms_config_repo import TenantSMSConfigRepository
from auth_engine.schemas.sms_config import (
    SMSConfigTestRequest,
    SMSConfigTestResponse,
    TenantSMSConfigCreate,
    TenantSMSConfigFallbackResponse,
    TenantSMSConfigResponse,
    TenantSMSConfigUpdate,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _credential_hint(encrypted: str) -> str:
    """Decrypt and return a safe hint (first 6 chars + ****)."""
    try:
        raw = SecurityUtils.decrypt_data(encrypted)
        return raw[:6] + "****" if len(raw) > 6 else raw[:3] + "****"
    except Exception:
        return "******"


def _to_response(row: TenantSMSConfigORM) -> TenantSMSConfigResponse:
    return TenantSMSConfigResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider.value,
        from_number=row.from_number,
        credential_hint=_credential_hint(row.encrypted_credentials),
        account_sid=row.account_sid,
        is_active=row.is_active,
    )


@router.get(
    "/{tenant_id}/sms-config",
    response_model=TenantSMSConfigResponse | TenantSMSConfigFallbackResponse,
    summary="Get tenant SMS configuration",
)
async def get_sms_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantSMSConfigResponse | TenantSMSConfigFallbackResponse:
    query = select(TenantSMSConfigORM).where(
        TenantSMSConfigORM.tenant_id == tenant_id
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()

    if not row:
        return TenantSMSConfigFallbackResponse(
            platform_provider=settings.SMS_PROVIDER,
            platform_from_number=settings.SMS_SENDER,
        )

    return _to_response(row)


@router.post(
    "/{tenant_id}/sms-config",
    response_model=TenantSMSConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant SMS configuration",
)
async def create_sms_config(
    tenant_id: uuid.UUID,
    body: TenantSMSConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSMSConfigResponse:
    # Check existing
    query = select(TenantSMSConfigORM).where(
        TenantSMSConfigORM.tenant_id == tenant_id
    )
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SMS config already exists for this tenant. Use PUT to update.",
        )

    row = TenantSMSConfigORM(
        tenant_id=tenant_id,
        provider=ModelSMSProviderType(body.provider.value),
        encrypted_credentials=SecurityUtils.encrypt_data(body.api_key),
        from_number=body.from_number,
        account_sid=body.account_sid,
        is_active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.put(
    "/{tenant_id}/sms-config",
    response_model=TenantSMSConfigResponse,
    summary="Update tenant SMS configuration",
)
async def update_sms_config(
    tenant_id: uuid.UUID,
    body: TenantSMSConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSMSConfigResponse:
    query = select(TenantSMSConfigORM).where(
        TenantSMSConfigORM.tenant_id == tenant_id
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SMS config found for this tenant.",
        )

    if body.provider is not None:
        row.provider = ModelSMSProviderType(body.provider.value)
    if body.api_key is not None:
        row.encrypted_credentials = SecurityUtils.encrypt_data(body.api_key)
    if body.from_number is not None:
        row.from_number = body.from_number
    if body.account_sid is not None:
        row.account_sid = body.account_sid
    if body.is_active is not None:
        row.is_active = body.is_active

    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete(
    "/{tenant_id}/sms-config",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant SMS configuration (falls back to platform default)",
)
async def delete_sms_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> None:
    query = select(TenantSMSConfigORM).where(
        TenantSMSConfigORM.tenant_id == tenant_id
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SMS config found for this tenant.",
        )

    await db.delete(row)
    await db.commit()


@router.post(
    "/{tenant_id}/sms-config/test",
    response_model=SMSConfigTestResponse,
    summary="Send a test SMS using the tenant's configured provider",
)
async def test_sms_config(
    tenant_id: uuid.UUID,
    body: SMSConfigTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> SMSConfigTestResponse:
    query = select(TenantSMSConfigORM).where(
        TenantSMSConfigORM.tenant_id == tenant_id
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No SMS config found for this tenant. Configure one first.",
        )

    try:
        repo = TenantSMSConfigRepository(db)
        resolver = SMSServiceResolver(repo)
        sms_service = await resolver.resolve(tenant_id)
        success = await sms_service.send_sms(
            body.to_number,
            "AuthEngine SMS Config Test — this is a test message.",
        )
        return SMSConfigTestResponse(success=success)
    except Exception as e:
        logger.error(f"SMS config test failed for tenant {tenant_id}: {e}")
        return SMSConfigTestResponse(success=False, error=str(e))
