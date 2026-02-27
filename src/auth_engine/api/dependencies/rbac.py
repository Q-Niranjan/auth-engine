import uuid
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.models import UserORM
from auth_engine.services.permission_service import PermissionService


def require_permission(
    *required_permissions: str,
) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    """
    Check if the user has ANY of the required permissions in the current context.
    If 'tenant_id' is in the path, it checks within that tenant.
    Otherwise, it checks the Platform context.
    """

    async def checker(
        request: Request,
        current_user: UserORM = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> UserORM:
        tenant_id = request.path_params.get("tenant_id")

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


def check_platform_permission(*permissions: str) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    """
    Dependency to check if the user has specific platform-level permissions.
    """

    async def checker(
        current_user: UserORM = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> UserORM:
        for perm in permissions:
            if await PermissionService.has_permission(db, current_user, perm, None):
                return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing platform permission: {', '.join(permissions)}",
        )

    return checker


def check_tenant_permission(*permissions: str) -> Callable[..., Coroutine[Any, Any, UserORM]]:
    """
    Dependency to check if the user has specific permissions within a tenant.
    Assumes 'tenant_id' is present in the path parameters.
    """

    async def checker(
        request: Request,
        current_user: UserORM = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> UserORM:
        tenant_id_str = request.path_params.get("tenant_id")
        if not tenant_id_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Tenant ID missing in path",
            )

        try:
            tenant_id = uuid.UUID(tenant_id_str)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid tenant ID format",
            ) from e

        for perm in permissions:
            if await PermissionService.has_permission(db, current_user, perm, tenant_id):
                return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing tenant permission: {', '.join(permissions)}",
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
