"""
Pydantic schemas for Tenant SMS Config endpoints.
"""

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SMSProviderType(str, Enum):
    TWILIO = "twilio"
    CONSOLE = "console"


class TenantSMSConfigCreate(BaseModel):
    """Body for POST /tenants/{tenant_id}/sms-config"""

    provider: SMSProviderType
    api_key: str = Field(..., min_length=1, description="Raw API key / auth token — encrypted")
    from_number: str = Field(..., min_length=1)
    account_sid: str | None = Field(None, description="Twilio account SID (if provider is twilio)")


class TenantSMSConfigUpdate(BaseModel):
    """Body for PUT /tenants/{tenant_id}/sms-config"""

    provider: SMSProviderType | None = None
    api_key: str | None = Field(None, description="If omitted, existing key is kept")
    from_number: str | None = None
    account_sid: str | None = None
    is_active: bool | None = None


class TenantSMSConfigResponse(BaseModel):
    """Response — never includes the real API key."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    from_number: str
    credential_hint: str  # first 6 chars + "****"
    account_sid: str | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TenantSMSConfigFallbackResponse(BaseModel):
    """Returned when tenant has no custom config."""

    configured: bool = False
    using_platform_default: bool = True
    platform_provider: str
    platform_from_number: str


class SMSConfigTestRequest(BaseModel):
    """Body for POST /tenants/{tenant_id}/sms-config/test"""

    to_number: str = Field(..., min_length=1)


class SMSConfigTestResponse(BaseModel):
    success: bool
    error: str | None = None
