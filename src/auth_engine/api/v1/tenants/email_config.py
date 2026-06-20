"""Tenant email configuration endpoints."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.security import SecurityUtils
from auth_engine.external_services.email.base import EmailProviderConfig
from auth_engine.external_services.email.factory import EmailServiceFactory
from auth_engine.models import UserORM
from auth_engine.models.email_config import EmailProviderType as ModelEmailProviderType
from auth_engine.models.email_config import TenantEmailConfigORM
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository
from auth_engine.schemas.email_config import (
    EmailConfigTestRequest,
    EmailConfigTestResponse,
    TenantEmailConfigCreate,
    TenantEmailConfigListResponse,
    TenantEmailConfigResponse,
    TenantEmailConfigUpdate,
)
from auth_engine.services.communications_config_service import (
    deactivate_other_email_configs,
    tenant_has_email_configs,
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


def _to_response(row: TenantEmailConfigORM) -> TenantEmailConfigResponse:
    return TenantEmailConfigResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider.value,
        from_email=row.from_email,
        credential_hint=_credential_hint(row.encrypted_credentials),
        is_active=row.is_active,
    )


async def _platform_default(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[str, str] | None:
    platform_id = await get_canonical_platform_tenant_id(db)
    if not platform_id or platform_id == tenant_id:
        return None
    repo = TenantEmailConfigRepository(db)
    active = await repo.get_active_by_tenant_id(platform_id)
    if not active:
        return None
    return active.provider.value, active.from_email


@router.get(
    "/{tenant_id}/email-config",
    response_model=TenantEmailConfigListResponse,
    summary="List tenant email configurations",
)
async def list_email_configs(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantEmailConfigListResponse:
    repo = TenantEmailConfigRepository(db)
    rows = await repo.list_by_tenant_id(tenant_id)
    platform_default = await _platform_default(db, tenant_id)
    has_active = any(row.is_active for row in rows)

    return TenantEmailConfigListResponse(
        items=[_to_response(row) for row in rows],
        using_platform_default=not has_active and platform_default is not None,
        platform_provider=platform_default[0] if platform_default else None,
        platform_from_email=platform_default[1] if platform_default else None,
    )


@router.post(
    "/{tenant_id}/email-config",
    response_model=TenantEmailConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant email configuration",
)
async def create_email_config(
    tenant_id: uuid.UUID,
    body: TenantEmailConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantEmailConfigResponse:
    activate = body.set_active or not await tenant_has_email_configs(db, tenant_id)
    row = TenantEmailConfigORM(
        tenant_id=tenant_id,
        provider=ModelEmailProviderType(body.provider.value),
        encrypted_credentials=SecurityUtils.encrypt_data(body.api_key),
        from_email=body.from_email,
        is_active=activate,
    )
    db.add(row)
    await db.flush()
    if activate:
        await deactivate_other_email_configs(db, tenant_id, keep_id=row.id)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.put(
    "/{tenant_id}/email-config/{config_id}",
    response_model=TenantEmailConfigResponse,
    summary="Update tenant email configuration",
)
async def update_email_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    body: TenantEmailConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantEmailConfigResponse:
    repo = TenantEmailConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email config not found.")

    if body.provider is not None:
        row.provider = ModelEmailProviderType(body.provider.value)
    if body.api_key is not None:
        row.encrypted_credentials = SecurityUtils.encrypt_data(body.api_key)
    if body.from_email is not None:
        row.from_email = body.from_email
    if body.set_active is True:
        row.is_active = True
        await deactivate_other_email_configs(db, tenant_id, keep_id=row.id)
    elif body.set_active is False:
        row.is_active = False

    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete(
    "/{tenant_id}/email-config/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant email configuration",
)
async def delete_email_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> None:
    repo = TenantEmailConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email config not found.")
    await db.delete(row)
    await db.commit()


@router.post(
    "/{tenant_id}/email-config/{config_id}/test",
    response_model=EmailConfigTestResponse,
    summary="Send a test email using a specific configuration",
)
async def test_email_config(
    tenant_id: uuid.UUID,
    config_id: uuid.UUID,
    body: EmailConfigTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> EmailConfigTestResponse:
    repo = TenantEmailConfigRepository(db)
    row = await repo.get_by_id(tenant_id, config_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email config not found.")

    try:
        api_key = SecurityUtils.decrypt_data(row.encrypted_credentials)
        email_service = EmailServiceFactory.create(
            EmailProviderConfig(
                provider_type=row.provider.value,
                api_key=api_key,
                from_email=row.from_email,
                is_active=row.is_active,
            )
        )
        await email_service.send_email(
            [str(body.to_email)],
            "AuthEngine Email Config Test",
            "<h1>Test Email</h1><p>Your tenant email configuration is working correctly.</p>",
        )
        return EmailConfigTestResponse(success=True)
    except Exception as e:
        logger.error(
            "Email config test failed for tenant %s config %s: %s", tenant_id, config_id, e
        )
        return EmailConfigTestResponse(success=False, error=str(e))
