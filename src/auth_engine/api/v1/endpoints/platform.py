import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.deps import get_db
from auth_engine.api.rbac import require_permission
from auth_engine.models import TenantORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.tenant import TenantResponse
from auth_engine.schemas.user import UserResponse
from auth_engine.services.user_service import UserService

router = APIRouter()


@router.get("/users", response_model=list[UserResponse])
async def list_all_users(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("platform.users.view")),
) -> list[UserORM]:
    """
    List all users globally across the platform.
    Requires platform admin privileges.
    """
    query = select(UserORM).options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
    result = await db.execute(query)
    return list(result.unique().scalars().all())


@router.get("/tenants", response_model=list[TenantResponse])
async def list_all_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("platform.tenants.view")),
) -> list[TenantORM]:
    """
    List all tenants globally.
    Requires platform admin privileges.
    """
    query = select(TenantORM)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_global_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(require_permission("platform.users.manage")),
) -> None:
    """
    Delete a user globally from the platform.
    Only SUPER_ADMIN can perform this action.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    success = await user_service.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
