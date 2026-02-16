import uuid
from datetime import datetime, timedelta
from typing import Any

from auth_engine.core.config import settings
from auth_engine.core.security import security, token_manager
from auth_engine.models.user import UserCreate, UserLogin, UserORM, UserStatus
from auth_engine.repositories.user_repo import UserRepository


class AuthService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def register_user(self, user_in: UserCreate) -> UserORM:
        # Check if user exists
        existing_user = await self.user_repo.get_by_email(user_in.email)
        if existing_user:
            raise ValueError("User with this email already exists")

        if user_in.username:
            existing_user = await self.user_repo.get_by_username(user_in.username)
            if existing_user:
                raise ValueError("Username already taken")

        # Hash password
        password_hash = security.hash_password(user_in.password)

        # Create user object
        user_data = {
            "id": str(uuid.uuid4()),
            "email": user_in.email,
            "username": user_in.username,
            "password_hash": password_hash,
            "first_name": user_in.first_name,
            "last_name": user_in.last_name,
            "status": UserStatus.ACTIVE,
            "auth_strategies": [user_in.auth_strategy.value],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        user = await self.user_repo.create(user_data)
        await self.user_repo.session.commit()
        return user

    async def authenticate_user(self, login_data: UserLogin) -> UserORM:
        user = await self.user_repo.get_by_email(login_data.email)
        if not user:
            raise ValueError("Invalid email or password")

        if not user.password_hash or not security.verify_password(
            login_data.password, str(user.password_hash)
        ):
            # TODO: Increment failed login attempts
            raise ValueError("Invalid email or password")

        if user.status != UserStatus.ACTIVE:
            raise ValueError(f"User account is {user.status}")

        # Update last login
        user.last_login_at = datetime.utcnow()  # type: ignore[assignment]
        await self.user_repo.session.commit()

        return user

    def create_tokens(self, user: UserORM) -> dict[str, Any]:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        user_data = {"sub": user.id, "email": user.email}

        access_token = token_manager.create_access_token(
            data=user_data, expires_delta=access_token_expires
        )
        refresh_token = token_manager.create_refresh_token(
            data=user_data, expires_delta=refresh_token_expires
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user,
        }
