import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from auth_engine.core.config import settings
from auth_engine.core.security import security, token_manager
from auth_engine.models import RoleORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserCreate, UserLogin, UserStatus

logger = logging.getLogger(__name__)


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

        if user_in.phone_number:
            existing_user = await self.user_repo.get_by_phone_number(user_in.phone_number)
            if existing_user:
                raise ValueError("User with this phone number already exists")

        # Hash password
        password_hash = security.hash_password(user_in.password)

        # Create user object
        user_data = {
            "id": str(uuid.uuid4()),
            "email": user_in.email,
            "username": user_in.username,
            "phone_number": user_in.phone_number,
            "password_hash": password_hash,
            "first_name": user_in.first_name,
            "last_name": user_in.last_name,
            "status": UserStatus.ACTIVE,
            "auth_strategies": [user_in.auth_strategy.value],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        user = await self.user_repo.create(user_data)

        # Assign default role TENANT_USER in the Platform Tenant context
        from auth_engine.models.tenant import TenantORM, TenantType
        
        role_query = select(RoleORM).where(RoleORM.name == "TENANT_USER")
        role_result = await self.user_repo.session.execute(role_query)
        tenant_user_role = role_result.scalar_one_or_none()

        if tenant_user_role:
            # Find the Platform tenant
            platform_query = select(TenantORM.id).where(TenantORM.type == TenantType.PLATFORM)
            platform_result = await self.user_repo.session.execute(platform_query)
            platform_tenant_id = platform_result.scalar()

            if platform_tenant_id:
                user_role = UserRoleORM(
                    user_id=user.id,
                    role_id=tenant_user_role.id,
                    tenant_id=platform_tenant_id,
                )
                self.user_repo.session.add(user_role)
            else:
                logger.warning("Platform tenant not found during user registration. Role not assigned.")

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

    def create_tokens(self, user: UserORM, session_id: str | None = None) -> dict[str, Any]:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        # Prepare roles and permissions for embedding in JWT
        roles = []
        permissions = set()
        for ur in user.roles:
            role_name = ur.role.name
            roles.append(
                {"name": role_name, "tenant_id": str(ur.tenant_id) if ur.tenant_id else None}
            )
            for rp in ur.role.permissions:
                permissions.add(rp.permission.name)

        user_data = {
            "sub": str(user.id),
            "email": str(user.email),
            "roles": roles,
            "permissions": list(permissions),
            "sid": session_id,
        }

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

    async def initiate_password_reset(self, email: str) -> None:
        user = await self.user_repo.get_by_email(email)
        if not user:
            # We don't reveal if user exists for security
            return

        # TODO: Generate reset token and send email
        logger.info(f"Password reset initiated for {email}")
