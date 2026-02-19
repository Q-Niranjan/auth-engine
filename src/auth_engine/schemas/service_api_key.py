import uuid
from datetime import datetime

from pydantic import BaseModel


class CreateApiKeyRequest(BaseModel):
    service_name: str
    tenant_id: uuid.UUID | None = None  # Scope the key to a specific tenant
    expires_at: datetime | None = None  # Optional expiry


class CreateApiKeyResponse(BaseModel):
    id: uuid.UUID
    service_name: str
    key_prefix: str
    tenant_id: uuid.UUID | None = None
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
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime

    class Config:
        from_attributes = True
