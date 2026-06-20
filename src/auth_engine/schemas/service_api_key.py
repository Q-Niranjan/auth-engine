import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class CreateApiKeyRequest(BaseModel):
    service_name: str
    tenant_id: uuid.UUID | None = None  # Scope the key to a specific tenant
    expires_at: datetime | None = None  # Optional expiry


class ApiKeyCreatorInfo(BaseModel):
    id: uuid.UUID
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class CreateApiKeyResponse(BaseModel):
    id: uuid.UUID
    service_name: str
    key_prefix: str
    tenant_id: uuid.UUID | None = None
    created_by: uuid.UUID | None = None
    creator: ApiKeyCreatorInfo | None = None
    expires_at: datetime | None = None
    created_at: datetime
    # The raw key is ONLY shown here — once. It is never stored.
    raw_key: str


class ApiKeyListItem(BaseModel):
    id: uuid.UUID
    service_name: str
    key_prefix: str
    tenant_id: uuid.UUID | None = None
    is_active: bool
    created_by: uuid.UUID | None = None
    creator: ApiKeyCreatorInfo | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
