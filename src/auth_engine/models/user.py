# models/user.py

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String
from sqlalchemy import Enum as SQLEnum

from auth_engine.core.postgres import Base


class AuthStrategy(str, Enum):
    EMAIL_PASSWORD = "email_password"  # pragma: allowlist secret
    # TODO: Add strategy in future days


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class UserORM(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    phone_number = Column(String(20), unique=True, index=True, nullable=True)

    # Password (nullable for OAuth-only users)
    password_hash = Column(String(255), nullable=True)

    # Profile
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    avatar_url = Column(String(500), nullable=True)

    # Status
    status: Column[UserStatus] = Column(
        SQLEnum(UserStatus), default=UserStatus.PENDING_VERIFICATION, nullable=False
    )
    is_email_verified = Column(Boolean, default=False, nullable=False)
    is_phone_verified = Column(Boolean, default=False, nullable=False)

    # Metadata
    auth_strategies = Column(JSON, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    password_changed_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)


class UserBase(BaseModel):
    email: EmailStr
    username: str | None = None
    phone_number: str | None = None
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


class UserResponse(UserBase):
    id: str
    status: UserStatus
    is_email_verified: bool
    is_phone_verified: bool
    auth_strategies: list[str]
    avatar_url: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None

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
