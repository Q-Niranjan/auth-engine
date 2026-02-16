from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.deps import get_db
from auth_engine.models.user import UserCreate, UserLogin, UserLoginResponse, UserResponse
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)) -> UserResponse:
    user_repo = UserRepository(db)
    auth_service = AuthService(user_repo)
    try:
        user = await auth_service.register_user(user_in)
        return UserResponse.model_validate(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/login", response_model=UserLoginResponse)
async def login(login_data: UserLogin, db: AsyncSession = Depends(get_db)) -> UserLoginResponse:
    user_repo = UserRepository(db)
    auth_service = AuthService(user_repo)
    try:
        user = await auth_service.authenticate_user(login_data)
        tokens = auth_service.create_tokens(user)
        return UserLoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
            user=UserResponse.model_validate(tokens["user"]),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e
