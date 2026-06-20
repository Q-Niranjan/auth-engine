import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


class TenantType(str, Enum):
    PLATFORM = "PLATFORM"
    CUSTOMER = "CUSTOMER"


class TenantBase(BaseModel):
    name: str | None = None
    description: str | None = None
    type: TenantType | None = None
    owner_id: uuid.UUID


class TenantCreate(TenantBase):
    name: str
    type: TenantType = TenantType.CUSTOMER

    @field_validator("type")
    @classmethod
    def reject_platform_type_on_create(cls, value: TenantType) -> TenantType:
        if value == TenantType.PLATFORM:
            raise ValueError("Platform tenants cannot be created via the API")
        return value


class TenantUpdate(TenantBase):
    @field_validator("type")
    @classmethod
    def reject_platform_type_on_update(cls, value: TenantType | None) -> TenantType | None:
        if value == TenantType.PLATFORM:
            raise ValueError("Cannot set organization type to platform")
        return value


class OwnerInfo(BaseModel):
    id: uuid.UUID
    email: EmailStr
    first_name: str | None = None
    last_name: str | None = None

    model_config = ConfigDict(from_attributes=True)


class TenantResponse(TenantBase):
    id: uuid.UUID
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    owner: OwnerInfo | None = None

    model_config = ConfigDict(from_attributes=True)


class TenantInviteRequest(BaseModel):
    email: EmailStr
    role_name: str = "TENANT_USER"
    role_id: uuid.UUID | None = None
