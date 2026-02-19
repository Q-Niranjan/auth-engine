import uuid

from fastapi import APIRouter, Depends

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.models import UserORM
from auth_engine.schemas.tenant import TenantResponse
from auth_engine.schemas.user import UserResponse

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: UserORM = Depends(get_current_active_user),
) -> UserResponse:
    """
    Get current user information.
    """
    return UserResponse.model_validate(current_user)


@router.get("/me/tenants", response_model=list[TenantResponse])
async def get_my_tenants(
    current_user: UserORM = Depends(get_current_active_user),
) -> list[TenantResponse]:
    """
    List all tenants the current user belongs to.
    """
    tenants = []
    for ur in current_user.roles:
        if ur.tenant and ur.tenant not in tenants:
            tenants.append(ur.tenant)
    return tenants


@router.get("/me/tenants/{tenant_id}/permissions")
async def get_my_tenant_permissions(
    tenant_id: uuid.UUID, current_user: UserORM = Depends(get_current_active_user)
) -> dict:
    """
    Get permissions for the current user in a specific tenant.
    """
    permissions = set()
    for ur in current_user.roles:
        if ur.tenant_id == tenant_id:
            for rp in ur.role.permissions:
                permissions.add(rp.permission.name)

    return {"tenant_id": tenant_id, "permissions": list(permissions)}
