"""
Pydantic schemas for Tenant SMS Config endpoints.
"""

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SMSProviderType(str, Enum):
    """Providers with a working SMSServiceFactory implementation."""

    TWILIO = "twilio"
    ANDROID_GATEWAY = "android_gateway"


class TenantSMSConfigCreate(BaseModel):
    provider: SMSProviderType
    api_key: str = Field(..., min_length=1, description="Raw API key / auth token — encrypted")
    from_number: str = Field(..., min_length=1)
    account_sid: str | None = Field(
        None, description="Twilio account SID, or Android gateway base URL"
    )
    set_active: bool = Field(
        default=True,
        description="Activate this config (deactivates other configs for the tenant)",
    )


class TenantSMSConfigUpdate(BaseModel):
    provider: SMSProviderType | None = None
    api_key: str | None = Field(None, description="If omitted, existing key is kept")
    from_number: str | None = None
    account_sid: str | None = None
    set_active: bool | None = Field(
        default=None,
        description="When true, activate this config and deactivate others",
    )


class TenantSMSConfigResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    from_number: str
    credential_hint: str
    account_sid: str | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TenantSMSConfigListResponse(BaseModel):
    items: list[TenantSMSConfigResponse]
    available_providers: list[str] = Field(
        default_factory=lambda: [p.value for p in SMSProviderType]
    )
    using_platform_default: bool = False
    platform_provider: str | None = None
    platform_from_number: str | None = None


class SMSConfigTestRequest(BaseModel):
    to_number: str = Field(..., min_length=1)


class SMSConfigTestResponse(BaseModel):
    success: bool
    error: str | None = None
