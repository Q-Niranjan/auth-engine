from fastapi import APIRouter, Depends

from auth_engine.api.auth_deps import get_current_active_user
from auth_engine.models.user import UserORM, UserResponse

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
