import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field

from .rbac import UserRoleResponse


class AuthStrategy(str, Enum):
    EMAIL_PASSWORD = "email_password"  # pragma: allowlist secret


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class UserBase(BaseModel):
    email: EmailStr
    phone_number: str | None = None
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)
    auth_strategy: AuthStrategy = AuthStrategy.EMAIL_PASSWORD


class UserUpdate(BaseModel):
    username: str | None = None
    phone_number: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    avatar_url: str | None = None


class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


class PasswordReset(BaseModel):
    email: EmailStr
    tenant_id: uuid.UUID | None = None


class UserResponse(UserBase):
    id: uuid.UUID
    status: UserStatus
    is_email_verified: bool
    is_phone_verified: bool
    auth_strategies: list[str] | None = None
    avatar_url: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
    roles: list[UserRoleResponse] = []

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenRefresh(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserSession(BaseModel):
    session_id: str
    user_id: uuid.UUID
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime
    expires_at: datetime
