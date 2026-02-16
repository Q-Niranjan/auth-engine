import uuid

from pydantic import BaseModel, ConfigDict


class TenantBase(BaseModel):
    name: str | None = None
    description: str | None = None


class TenantCreate(TenantBase):
    name: str


class TenantUpdate(TenantBase):
    pass


class TenantResponse(TenantBase):
    id: uuid.UUID

    model_config = ConfigDict(from_attributes=True)
