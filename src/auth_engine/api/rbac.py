import uuid
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, status

from auth_engine.api.auth_deps import get_current_user
from auth_engine.models import UserORM


def require_role(*allowed_roles: str) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    async def checker(
        current_user: UserORM = Depends(get_current_user),
    ) -> UserORM:
        # We need to ensure roles and their nested data are loaded
        # Since we use AsyncSession, we might need to be careful about lazy loading
        # In current_user (fetched in get_current_user), it depends on how it was loaded.
        # Assuming the repo or dependency loaded it correctly or we use joinload.

        user_roles = [ur.role.name for ur in current_user.roles]

        if not any(role in allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )

        return current_user

    return checker


def require_permission(
    *required_permissions: str,
) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    async def checker(
        current_user: UserORM = Depends(get_current_user),
    ) -> UserORM:
        user_perms = set()
        for ur in current_user.roles:
            for rp in ur.role.permissions:
                user_perms.add(rp.permission.name)

        if not any(perm in user_perms for perm in required_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

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
