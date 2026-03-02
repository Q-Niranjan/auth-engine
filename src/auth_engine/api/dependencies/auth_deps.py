import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.redis import get_redis
from auth_engine.core.security import token_manager
from auth_engine.models import RoleORM, RolePermissionORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository

security = HTTPBearer()
bearer_optional = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> UserORM:
    """
    Dependency to get the current authenticated user from JWT token.
    """
    token = credentials.credentials

    try:
        payload = token_manager.verify_access_token(token)
        user_id: str | None = payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    session_id = payload.get("sid")
    if session_id:
        redis = await get_redis()
        session_exists = await redis.exists(f"session:{user_id}:{session_id}")
        if not session_exists:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked or expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Fetch user from database with roles and permissions eager loaded
    query = (
        select(UserORM)
        .where(UserORM.id == user_id)
        .options(
            joinedload(UserORM.roles)
            .joinedload(UserRoleORM.role)
            .joinedload(RoleORM.permissions)
            .joinedload(RolePermissionORM.permission)
        )
        .options(joinedload(UserORM.roles).joinedload(UserRoleORM.tenant))
    )
    result = await db.execute(query)
    user = result.unique().scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(current_user: UserORM = Depends(get_current_user)) -> UserORM:
    """
    Dependency to get the current active user.
    """
    from auth_engine.schemas.user import UserStatus

    if current_user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User account is {current_user.status.value}",
        )

    return current_user


async def get_current_active_superadmin(
    current_user: UserORM = Depends(get_current_active_user),
) -> UserORM:
    """
    Dependency to get the current active superuser.
    """
    is_super_admin = False
    for user_role in current_user.roles:
        if user_role.role.name == "SUPER_ADMIN":
            is_super_admin = True
            break

    if not is_super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="The user doesn't have enough privileges"
        )
    return current_user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_optional),
    db: AsyncSession = Depends(get_db),
) -> UserORM | None:
    """
    Like get_current_user but returns None instead of 401.
    Used by OIDC /authorize to check for an existing authenticated session.
    If a valid token is present, returns the user — otherwise returns None
    and the authorize endpoint shows the login page.
    """
    if not credentials:
        return None

    try:
        payload = token_manager.verify_access_token(credentials.credentials)
        user_id_str = payload.get("sub")
        if not user_id_str:
            return None

        user_repo = UserRepository(db)
        return await user_repo.get(uuid.UUID(user_id_str))
    except Exception:
        return None
