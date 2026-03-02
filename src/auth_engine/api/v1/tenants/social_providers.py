"""
Tenant Social Provider endpoints.

GET    /tenants/{tenant_id}/social-providers
POST   /tenants/{tenant_id}/social-providers
PUT    /tenants/{tenant_id}/social-providers/{provider}
DELETE /tenants/{tenant_id}/social-providers/{provider}
PATCH  /tenants/{tenant_id}/social-providers/{provider}/toggle
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.security import SecurityUtils
from auth_engine.models import UserORM
from auth_engine.models.tenant_social_provider import TenantSocialProviderORM
from auth_engine.schemas.tenant_social_provider import (
    TenantSocialProviderCreate,
    TenantSocialProviderResponse,
    TenantSocialProviderToggle,
    TenantSocialProviderUpdate,
)

router = APIRouter()


def _make_prefix(raw_secret: str) -> str:
    """Return the first 8 chars of the raw secret for safe display."""
    return raw_secret[:8] + "****" if len(raw_secret) > 8 else raw_secret[:4] + "****"


def _to_response(row: TenantSocialProviderORM) -> TenantSocialProviderResponse:
    return TenantSocialProviderResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        provider=row.provider,
        client_id=row.client_id,  # stored encrypted — callers see the ciphertext (not raw)
        client_secret_prefix=row.client_secret_prefix,
        redirect_uri=row.redirect_uri,
        oidc_discovery_url=row.oidc_discovery_url,
        is_active=row.is_active,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get(
    "/{tenant_id}/social-providers",
    response_model=list[TenantSocialProviderResponse],
    summary="List tenant social providers",
)
async def list_social_providers(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> list[TenantSocialProviderResponse]:
    query = select(TenantSocialProviderORM).where(TenantSocialProviderORM.tenant_id == tenant_id)
    result = await db.execute(query)
    rows = result.scalars().all()
    return [_to_response(r) for r in rows]


@router.post(
    "/{tenant_id}/social-providers",
    response_model=TenantSocialProviderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant social provider credentials",
)
async def create_social_provider(
    tenant_id: uuid.UUID,
    body: TenantSocialProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSocialProviderResponse:
    # Check for existing config
    query = select(TenantSocialProviderORM).where(
        TenantSocialProviderORM.tenant_id == tenant_id,
        TenantSocialProviderORM.provider == body.provider.value,
    )
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Provider '{body.provider.value}' already configured for this tenant. "
            f"Use PUT to update.",
        )

    row = TenantSocialProviderORM(
        tenant_id=tenant_id,
        provider=body.provider.value,
        client_id=SecurityUtils.encrypt_data(body.client_id),
        client_secret=SecurityUtils.encrypt_data(body.client_secret),
        client_secret_prefix=_make_prefix(body.client_secret),
        redirect_uri=body.redirect_uri,
        oidc_discovery_url=body.oidc_discovery_url,
        is_active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.put(
    "/{tenant_id}/social-providers/{provider}",
    response_model=TenantSocialProviderResponse,
    summary="Update tenant social provider credentials",
)
async def update_social_provider(
    tenant_id: uuid.UUID,
    provider: str,
    body: TenantSocialProviderUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSocialProviderResponse:
    query = select(TenantSocialProviderORM).where(
        TenantSocialProviderORM.tenant_id == tenant_id,
        TenantSocialProviderORM.provider == provider.lower(),
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No '{provider}' provider configured for this tenant.",
        )

    if body.client_id is not None:
        row.client_id = SecurityUtils.encrypt_data(body.client_id)
    if body.client_secret is not None:
        row.client_secret = SecurityUtils.encrypt_data(body.client_secret)
        row.client_secret_prefix = _make_prefix(body.client_secret)
    if body.redirect_uri is not None:
        row.redirect_uri = body.redirect_uri
    if body.oidc_discovery_url is not None:
        row.oidc_discovery_url = body.oidc_discovery_url
    if body.is_active is not None:
        row.is_active = body.is_active

    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete(
    "/{tenant_id}/social-providers/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tenant social provider credentials",
)
async def delete_social_provider(
    tenant_id: uuid.UUID,
    provider: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> None:
    query = select(TenantSocialProviderORM).where(
        TenantSocialProviderORM.tenant_id == tenant_id,
        TenantSocialProviderORM.provider == provider.lower(),
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No '{provider}' provider configured for this tenant.",
        )

    await db.delete(row)
    await db.commit()


@router.patch(
    "/{tenant_id}/social-providers/{provider}/toggle",
    response_model=TenantSocialProviderResponse,
    summary="Toggle tenant social provider active state",
)
async def toggle_social_provider(
    tenant_id: uuid.UUID,
    provider: str,
    body: TenantSocialProviderToggle,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantSocialProviderResponse:
    query = select(TenantSocialProviderORM).where(
        TenantSocialProviderORM.tenant_id == tenant_id,
        TenantSocialProviderORM.provider == provider.lower(),
    )
    result = await db.execute(query)
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No '{provider}' provider configured for this tenant.",
        )

    row.is_active = body.is_active
    await db.commit()
    await db.refresh(row)
    return _to_response(row)
