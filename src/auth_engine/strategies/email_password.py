# strategies/email_password.py
import uuid
from typing import Any

from auth_engine.core.config import settings
from auth_engine.core.exceptions import (
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
    WeakPasswordError,
)
from auth_engine.core.security import security, token_manager
from auth_engine.strategies.base import PasswordBasedStrategy


class EmailPasswordStrategy(PasswordBasedStrategy):
    def __init__(self, user_repository: Any):
        super().__init__("email_password")
        self.user_repo = user_repository

    async def authenticate(self, credentials: dict[str, Any]) -> dict[str, Any]:
        email = credentials.get("email")
        password = credentials.get("password")

        if not email or not password:
            raise InvalidCredentialsError("Email and password are required")

        # Find user by email
        user = await self.user_repo.get_by_email(email)
        if not user:
            raise InvalidCredentialsError("User not exist for this credentials")

        # Verify password
        if not user.get("password_hash"):
            raise InvalidCredentialsError("Password authentication not available for this account")

        if not security.verify_password(password, user["password_hash"]):
            raise InvalidCredentialsError()

        # Check if user is active
        if user.get("status") != "active":
            raise InvalidCredentialsError(f"Account is {user.get('status')}")

        # Generate tokens
        access_token = token_manager.create_access_token(
            data={"sub": user["id"], "email": user["email"], "strategy": self.name}
        )

        refresh_token = token_manager.create_refresh_token(
            data={"sub": user["id"], "email": user["email"]}
        )

        # Update last login
        await self.user_repo.update_last_login(user["id"])

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": self._sanitize_user_data(user),
        }

    async def validate(self, token: str) -> dict[str, Any]:
        try:
            payload = token_manager.verify_access_token(token)

            user_id = payload.get("sub")
            if not user_id:
                raise InvalidCredentialsError("Invalid token payload")

            # Get user from database
            user = await self.user_repo.get_by_id(user_id)

            if not user:
                raise UserNotFoundError()

            return self._sanitize_user_data(user)

        except Exception as e:
            raise InvalidCredentialsError(f"Token validation failed: {str(e)}") from e

    async def register(self, user_data: dict[str, Any]) -> dict[str, Any]:
        email = user_data.get("email")
        password = user_data.get("password")

        if not email or not password:
            raise InvalidCredentialsError("Email and password are required")

        existing_user = await self.user_repo.get_by_email(email)
        if existing_user:
            raise UserAlreadyExistsError(f"User with email {email} already exists")

        is_valid, error_msg = security.validate_password_strength(password)
        if not is_valid:
            raise WeakPasswordError(error_msg)

        password_hash = security.hash_password(password)
        user_id = str(uuid.uuid4())
        new_user = {
            "id": user_id,
            "email": email,
            "password_hash": password_hash,
            "username": user_data.get("username"),
            "first_name": user_data.get("first_name"),
            "last_name": user_data.get("last_name"),
            "status": "pending_verification",
            "is_email_verified": False,
            "is_phone_verified": False,
            "auth_strategies": [self.name],
        }

        created_user = await self.user_repo.create(new_user)
        # TODO: Send verification email

        return self._sanitize_user_data(created_user)

    async def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        if not security.verify_password(current_password, user["password_hash"]):
            raise InvalidCredentialsError("Current password is incorrect")

        is_valid, error_msg = security.validate_password_strength(new_password)
        if not is_valid:
            raise WeakPasswordError(error_msg)

        new_password_hash = security.hash_password(new_password)

        await self.user_repo.update_password(user_id, new_password_hash)
        return True

    def _sanitize_user_data(self, user: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive data from user object"""
        sensitive_fields = ["password_hash"]
        return {k: v for k, v in user.items() if k not in sensitive_fields}
