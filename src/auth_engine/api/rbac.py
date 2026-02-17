import uuid
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, status

from auth_engine.api.auth_deps import get_current_user
from auth_engine.api.deps import get_db
from auth_engine.models import UserORM
from auth_engine.services.permission_service import PermissionService
from sqlalchemy.ext.asyncio import AsyncSession


def require_permission(
    *required_permissions: str,
) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    """
    Check if the user has ANY of the required permissions in the current context.
    If 'tenant_id' is in the path, it checks within that tenant.
    Otherwise, it checks the Platform context.
    """
    async def checker(
        current_user: UserORM = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
        tenant_id: str | None = None # This will pick up "tenant_id" from path if it exists
    ) -> UserORM:
        t_id = None
        if tenant_id:
            try:
                t_id = uuid.UUID(tenant_id)
            except ValueError:
                pass

        for perm in required_permissions:
            if await PermissionService.has_permission(db, current_user, perm, t_id):
                return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    return checker


def enforce_tenant_isolation(tenant_id_param: str) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    """
    Enforces that the current user belongs to the tenant specified in the request.
    """

    async def checker(
        current_user: UserORM = Depends(get_current_user),
    ) -> UserORM:
        try:
            target_tenant_id = uuid.UUID(tenant_id_param)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid tenant ID format"
            ) from None

        user_tenant_ids = [ur.tenant_id for ur in current_user.roles if ur.tenant_id is not None]

        # Super Admins might bypass this if they have platform scope
        is_super_admin = any(ur.role.name == "SUPER_ADMIN" for ur in current_user.roles)

        if not is_super_admin and target_tenant_id not in user_tenant_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this tenant"
            )

        return current_user

    return checker
