import uuid

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserResponse, UserSession
from auth_engine.services.session_service import SessionService
from auth_engine.services.user_service import UserService

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: UserORM = Depends(get_current_active_user),
) -> UserORM:
    """
    Get current authenticated user information.
    """
    return current_user


@router.get("/me/sessions", response_model=list[UserSession])
async def get_my_sessions(
    current_user: UserORM = Depends(get_current_active_user),
    redis_conn: redis.Redis = Depends(get_redis),
) -> list[UserSession]:
    """
    List all active sessions for the current user.
    """
    session_service = SessionService(redis_conn)
    return await session_service.list_sessions(current_user.id)


@router.delete("/me/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_session(
    session_id: str,
    current_user: UserORM = Depends(get_current_active_user),
    redis_conn: redis.Redis = Depends(get_redis),
) -> None:
    """
    Revoke a specific session for the current user.
    """
    session_service = SessionService(redis_conn)
    success = await session_service.delete_session(current_user.id, session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")


# --- Platform Admin Endpoints ---


@router.get("", response_model=list[UserResponse])
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


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
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

    try:
        success = await user_service.delete_user(user_id, actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
