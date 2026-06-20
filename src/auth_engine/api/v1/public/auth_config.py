"""
Public tenant auth configuration for login pages.

GET /auth/auth-config?tenant_id=<uuid>
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.schemas.tenant_auth_config import PublicTenantAuthConfigResponse
from auth_engine.services.tenant_auth_config_service import (
    get_or_create_auth_config,
    normalize_allowed_methods,
)

router = APIRouter()


@router.get(
    "/auth-config",
    response_model=PublicTenantAuthConfigResponse,
    summary="Public tenant auth methods for login UI",
)
async def get_public_auth_config(
    tenant_id: uuid.UUID = Query(..., description="Tenant whose login methods to expose"),
    db: AsyncSession = Depends(get_db),
) -> PublicTenantAuthConfigResponse:
    try:
        config = await get_or_create_auth_config(db, tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return PublicTenantAuthConfigResponse(
        tenant_id=config.tenant_id,
        allowed_methods=normalize_allowed_methods(config.allowed_methods),
    )
