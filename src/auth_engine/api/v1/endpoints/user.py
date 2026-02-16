import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, status

from auth_engine.api.auth_deps import get_current_active_user
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.schemas.user import UserResponse, UserSession
from auth_engine.services.session_service import SessionService

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: UserORM = Depends(get_current_active_user),
) -> UserORM:
    """
    Get current authenticated user information.
    Requires valid JWT token in Authorization header.
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
