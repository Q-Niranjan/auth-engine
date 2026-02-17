import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict


class TenantType(str, Enum):
    PLATFORM = "PLATFORM"
    CUSTOMER = "CUSTOMER"


class TenantBase(BaseModel):
    name: str | None = None
    description: str | None = None
    type: TenantType | None = None


class TenantCreate(TenantBase):
    name: str
    type: TenantType = TenantType.CUSTOMER


class TenantUpdate(TenantBase):
    pass


class TenantResponse(TenantBase):
    id: uuid.UUID

    model_config = ConfigDict(from_attributes=True)
