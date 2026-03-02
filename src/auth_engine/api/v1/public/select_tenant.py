"""
POST /auth/select-tenant — Issue a tenant-scoped JWT.

After a user logs in with a platform-scoped JWT, they call this endpoint
to get a tenant-scoped token that includes permissions and session TTL
specific to that tenant.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.security import token_manager
from auth_engine.models import TenantAuthConfigORM, TenantORM, UserORM, UserRoleORM
from auth_engine.schemas.select_tenant import SelectTenantRequest, SelectTenantResponse

router = APIRouter()


@router.post(
    "/select-tenant",
    response_model=SelectTenantResponse,
    summary="Select a tenant and receive a tenant-scoped JWT",
    description=(
        "Exchange a platform-scoped JWT for a tenant-scoped JWT. "
        "Validates user membership and tenant auth configuration."
    ),
)
async def select_tenant(
    body: SelectTenantRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_active_user),
) -> SelectTenantResponse:
    tenant_id = body.tenant_id

    # 1. Verify the tenant exists
    tenant_query = select(TenantORM).where(TenantORM.id == tenant_id)
    tenant_result = await db.execute(tenant_query)
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )

    # 2. Verify the user has a role in this tenant
    role_query = select(UserRoleORM).where(
        UserRoleORM.user_id == current_user.id,
        UserRoleORM.tenant_id == tenant_id,
    )
    role_result = await db.execute(role_query)
    user_roles = list(role_result.unique().scalars().all())

    if not user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this tenant.",
        )

    # 3. Load tenant auth config
    config_query = select(TenantAuthConfigORM).where(TenantAuthConfigORM.tenant_id == tenant_id)
    auth_config_result = await db.execute(config_query)
    auth_config = auth_config_result.scalar_one_or_none()

    session_ttl = 3600  # default
    if auth_config:
        session_ttl = auth_config.session_ttl_seconds

        # 4. Check domain restrictions
        if auth_config.allowed_domains:
            user_domain = str(current_user.email).split("@")[-1].lower()
            allowed = [d.lower() for d in auth_config.allowed_domains]
            if user_domain not in allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Email domain '{user_domain}' is not allowed for this tenant.",
                )

    # 5. Collect permissions for this tenant
    permissions: set[str] = set()
    for ur in user_roles:
        if hasattr(ur.role, "permissions"):
            for rp in ur.role.permissions:
                permissions.add(rp.permission.name)

    # 6. Issue tenant-scoped JWT
    token_data = {
        "sub": str(current_user.id),
        "email": str(current_user.email),
        "scope": "tenant",
        "tenant_id": str(tenant_id),
        "permissions": sorted(permissions),
        "strategy": "email_password",
    }

    expires_delta = timedelta(seconds=session_ttl)

    access_token = token_manager.create_access_token(data=token_data, expires_delta=expires_delta)
    refresh_token = token_manager.create_refresh_token(
        data={
            "sub": str(current_user.id),
            "email": str(current_user.email),
            "scope": "tenant",
            "tenant_id": str(tenant_id),
        }
    )

    return SelectTenantResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=session_ttl,
    )
