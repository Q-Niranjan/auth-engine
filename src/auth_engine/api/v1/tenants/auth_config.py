"""
Tenant Auth Config endpoints.

GET  /tenants/{tenant_id}/auth-config
PUT  /tenants/{tenant_id}/auth-config
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.models import TenantAuthConfigORM, UserORM
from auth_engine.schemas.tenant_auth_config import (
    VALID_AUTH_METHODS,
    TenantAuthConfigResponse,
    TenantAuthConfigUpdate,
)

router = APIRouter()


async def _get_or_404(db: AsyncSession, tenant_id: uuid.UUID) -> TenantAuthConfigORM:
    """Return the config or raise 404."""
    query = select(TenantAuthConfigORM).where(TenantAuthConfigORM.tenant_id == tenant_id)
    result = await db.execute(query)
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Auth config not found for this tenant. "
            "Config is auto-created when a tenant is created.",
        )
    return config


@router.get(
    "/{tenant_id}/auth-config",
    response_model=TenantAuthConfigResponse,
    summary="Get tenant auth configuration",
)
async def get_auth_config(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.view")),
) -> TenantAuthConfigResponse:
    config = await _get_or_404(db, tenant_id)
    return TenantAuthConfigResponse.model_validate(config)


@router.put(
    "/{tenant_id}/auth-config",
    response_model=TenantAuthConfigResponse,
    summary="Update tenant auth configuration",
)
async def update_auth_config(
    tenant_id: uuid.UUID,
    body: TenantAuthConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("tenant.update")),
) -> TenantAuthConfigResponse:
    config = await _get_or_404(db, tenant_id)

    if body.allowed_methods is not None:
        invalid = set(body.allowed_methods) - VALID_AUTH_METHODS
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid auth methods: {', '.join(invalid)}. "
                f"Valid values: {', '.join(sorted(VALID_AUTH_METHODS))}",
            )
        config.allowed_methods = body.allowed_methods

    if body.mfa_required is not None:
        config.mfa_required = body.mfa_required

    if body.password_policy is not None:
        config.password_policy = body.password_policy.model_dump()

    if body.session_ttl_seconds is not None:
        config.session_ttl_seconds = body.session_ttl_seconds

    if body.allowed_domains is not None:
        config.allowed_domains = body.allowed_domains

    if body.oidc_client_id is not None:
        config.oidc_client_id = body.oidc_client_id

    await db.commit()
    await db.refresh(config)
    return TenantAuthConfigResponse.model_validate(config)
