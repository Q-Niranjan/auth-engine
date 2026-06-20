"""Tenant SMS configuration endpoints."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.security import SecurityUtils
from auth_engine.external_services.sms.base import SMSProviderConfig
from auth_engine.external_services.sms.factory import SMSServiceFactory
from auth_engine.models import UserORM
from auth_engine.models.sms_config import SMSProviderType as ModelSMSProviderType
from auth_engine.models.sms_config import TenantSMSConfigORM
from auth_engine.repositories.sms_config_repo import TenantSMSConfigRepository
from auth_engine.schemas.sms_config import (
    SMSConfigTestRequest,
    SMSConfigTestResponse,
    TenantSMSConfigCreate,
    TenantSMSConfigListResponse,
    TenantSMSConfigResponse,
    TenantSMSConfigUpdate,
)
from auth_engine.services.communications_config_service import (
    deactivate_other_sms_configs,
    tenant_has_sms_configs,
)
from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id

logger = logging.getLogger(__name__)
router = APIRouter()


def _credential_hint(encrypted: str) -> str:
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


async def _platform_default(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[str, str] | None:
    platform_id = await get_canonical_platform_tenant_id(db)
    if not platform_id or platform_id == tenant_id:
        return None
    repo = TenantSMSConfigRepository(db)
    active = await repo.get_active_by_tenant_id(platform_id)
    if not active:
        return None
    return active.provider.value, active.from_number


@router.get(
    "/{tenant_id}/sms-config",
    response_model=TenantSMSConfigListResponse,
    summary="List tenant SMS configurations",
)
async def list_sms_configs(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantSMSConfigListResponse:
    repo = TenantSMSConfigRepository(db)
    rows = await repo.list_by_tenant_id(tenant_id)
    platform_default = await _platform_default(db, tenant_id)
    has_active = any(row.is_active for row in rows)

    return TenantSMSConfigListResponse(
        items=[_to_response(row) for row in rows],
        using_platform_default=not has_active and platform_default is not None,
        platform_provider=platform_default[0] if platform_default else None,
        platform_from_number=platform_default[1] if platform_default else None,
    )


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
    activate = body.set_active or not await tenant_has_sms_configs(db, tenant_id)
    row = TenantSMSConfigORM(
        tenant_id=tenant_id,
        provider=ModelSMSProviderType(body.provider.value),
        encrypted_credentials=SecurityUtils.encrypt_data(body.api_key),
        from_number=body.from_number,
        account_sid=body.account_sid,
        is_active=activate,
    )
    db.add(row)
    await db.flush()
    if activate:
        await deactivate_other_sms_configs(db, tenant_id, keep_id=row.id)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.put(
    "/{tenant_id}/sms-config/{config_id}",
    response_model=TenantSMSConfigResponse,
    summary="Update tenant SMS configuration",
)
async def update_sms_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    body: TenantSMSConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSMSConfigResponse:
    repo = TenantSMSConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SMS config not found.")

    if body.provider is not None:
        row.provider = ModelSMSProviderType(body.provider.value)
    if body.api_key is not None:
        row.encrypted_credentials = SecurityUtils.encrypt_data(body.api_key)
    if body.from_number is not None:
        row.from_number = body.from_number
    if body.account_sid is not None:
        row.account_sid = body.account_sid
    if body.set_active is True:
        row.is_active = True
        await deactivate_other_sms_configs(db, tenant_id, keep_id=row.id)
    elif body.set_active is False:
        row.is_active = False

    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete(
    "/{tenant_id}/sms-config/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant SMS configuration",
)
async def delete_sms_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> None:
    repo = TenantSMSConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SMS config not found.")
    await db.delete(row)
    await db.commit()


@router.post(
    "/{tenant_id}/sms-config/{config_id}/test",
    response_model=SMSConfigTestResponse,
    summary="Send a test SMS using a specific configuration",
)
async def test_sms_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    body: SMSConfigTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> SMSConfigTestResponse:
    repo = TenantSMSConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SMS config not found.")

    try:
        api_key = SecurityUtils.decrypt_data(row.encrypted_credentials)
        sms_service = SMSServiceFactory.create(
            SMSProviderConfig(
                provider_type=row.provider.value,
                api_key=api_key,
                from_number=row.from_number,
                is_active=row.is_active,
                account_sid=row.account_sid,
            )
        )
        success = await sms_service.send_sms(
            body.to_number,
            "AuthEngine SMS Config Test — this is a test message.",
        )
        return SMSConfigTestResponse(success=success)
    except Exception as e:
        logger.error("SMS config test failed for tenant %s config %s: %s", tenant_id, config_id, e)
        return SMSConfigTestResponse(success=False, error=str(e))
