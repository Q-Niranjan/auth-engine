"""
Tenant Email Config endpoints.

GET    /tenants/{tenant_id}/email-config
POST   /tenants/{tenant_id}/email-config
PUT    /tenants/{tenant_id}/email-config
DELETE /tenants/{tenant_id}/email-config
POST   /tenants/{tenant_id}/email-config/test

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
from auth_engine.external_services.email.resolver import EmailServiceResolver
from auth_engine.models import UserORM
from auth_engine.models.email_config import EmailProviderType as ModelEmailProviderType
from auth_engine.models.email_config import TenantEmailConfigORM
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository
from auth_engine.schemas.email_config import (
    EmailConfigTestRequest,
    EmailConfigTestResponse,
    TenantEmailConfigCreate,
    TenantEmailConfigFallbackResponse,
    TenantEmailConfigResponse,
    TenantEmailConfigUpdate,
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


def _to_response(row: TenantEmailConfigORM) -> TenantEmailConfigResponse:
    return TenantEmailConfigResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider.value,
        from_email=row.from_email,
        credential_hint=_credential_hint(row.encrypted_credentials),
        is_active=row.is_active,
    )


@router.get(
    "/{tenant_id}/email-config",
    response_model=TenantEmailConfigResponse | TenantEmailConfigFallbackResponse,
    summary="Get tenant email configuration",
)
async def get_email_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantEmailConfigResponse | TenantEmailConfigFallbackResponse:
    query = select(TenantEmailConfigORM).where(TenantEmailConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    row = result.scalar_one_or_none()

    if not row:
        return TenantEmailConfigFallbackResponse(
            platform_provider=settings.EMAIL_PROVIDER,
            platform_from_email=settings.EMAIL_SENDER,
        )

    return _to_response(row)


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
    # Check existing
    query = select(TenantEmailConfigORM).where(TenantEmailConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email config already exists for this tenant. Use PUT to update.",
        )

    row = TenantEmailConfigORM(
        tenant_id=tenant_id,
        provider=ModelEmailProviderType(body.provider.value),
        encrypted_credentials=SecurityUtils.encrypt_data(body.api_key),
        from_email=body.from_email,
        is_active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.put(
    "/{tenant_id}/email-config",
    response_model=TenantEmailConfigResponse,
    summary="Update tenant email configuration",
)
async def update_email_config(
    tenant_id: uuid.UUID,
    body: TenantEmailConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantEmailConfigResponse:
    query = select(TenantEmailConfigORM).where(TenantEmailConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No email config found for this tenant.",
        )

    if body.provider is not None:
        row.provider = ModelEmailProviderType(body.provider.value)
    if body.api_key is not None:
        row.encrypted_credentials = SecurityUtils.encrypt_data(body.api_key)
    if body.from_email is not None:
        row.from_email = body.from_email
    if body.is_active is not None:
        row.is_active = body.is_active

    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete(
    "/{tenant_id}/email-config",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant email configuration (falls back to platform default)",
)
async def delete_email_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> None:
    query = select(TenantEmailConfigORM).where(TenantEmailConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No email config found for this tenant.",
        )

    await db.delete(row)
    await db.commit()


@router.post(
    "/{tenant_id}/email-config/test",
    response_model=EmailConfigTestResponse,
    summary="Send a test email using the tenant's configured provider",
)
async def test_email_config(
    tenant_id: uuid.UUID,
    body: EmailConfigTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> EmailConfigTestResponse:
    query = select(TenantEmailConfigORM).where(TenantEmailConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No email config found for this tenant. Configure one first.",
        )

    try:
        repo = TenantEmailConfigRepository(db)
        resolver = EmailServiceResolver(repo)
        email_service = await resolver.resolve(tenant_id)
        await email_service.send_email(
            [str(body.to_email)],
            "AuthEngine Email Config Test",
            "<h1>Test Email</h1><p>Your tenant email configuration is working correctly.</p>",
        )
        return EmailConfigTestResponse(success=True)
    except Exception as e:
        logger.error(f"Email config test failed for tenant {tenant_id}: {e}")
        return EmailConfigTestResponse(success=False, error=str(e))
