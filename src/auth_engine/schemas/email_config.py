"""
Pydantic schemas for Tenant Email Config endpoints.
"""

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class EmailProviderType(str, Enum):
    SENDGRID = "sendgrid"
    SES = "ses"
    SMTP = "smtp"


class TenantEmailConfigCreate(BaseModel):
    """Body for POST /tenants/{tenant_id}/email-config"""

    provider: EmailProviderType
    api_key: str = Field(..., min_length=1, description="Raw API key — encrypted before storage")
    from_email: EmailStr


class TenantEmailConfigUpdate(BaseModel):
    """Body for PUT /tenants/{tenant_id}/email-config"""

    provider: EmailProviderType | None = None
    api_key: str | None = Field(None, description="If omitted, existing key is kept")
    from_email: EmailStr | None = None
    is_active: bool | None = None


class TenantEmailConfigResponse(BaseModel):
    """Response — never includes the real API key."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    from_email: str
    credential_hint: str  # first 6 chars + "****"
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TenantEmailConfigFallbackResponse(BaseModel):
    """Returned when tenant has no custom config."""

    configured: bool = False
    using_platform_default: bool = True
    platform_provider: str
    platform_from_email: str


class EmailConfigTestRequest(BaseModel):
    """Body for POST /tenants/{tenant_id}/email-config/test"""

    to_email: EmailStr


class EmailConfigTestResponse(BaseModel):
    success: bool
    error: str | None = None
