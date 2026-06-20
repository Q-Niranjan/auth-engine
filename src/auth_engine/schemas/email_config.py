"""
Pydantic schemas for Tenant Email Config endpoints.
"""

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class EmailProviderType(str, Enum):
    """Providers with a working EmailServiceFactory implementation."""

    SENDGRID = "sendgrid"
    SES = "ses"


class TenantEmailConfigCreate(BaseModel):
    provider: EmailProviderType
    api_key: str = Field(..., min_length=1, description="Raw API key — encrypted before storage")
    from_email: EmailStr
    set_active: bool = Field(
        default=True,
        description="Activate this config (deactivates other configs for the tenant)",
    )


class TenantEmailConfigUpdate(BaseModel):
    provider: EmailProviderType | None = None
    api_key: str | None = Field(None, description="If omitted, existing key is kept")
    from_email: EmailStr | None = None
    set_active: bool | None = Field(
        default=None,
        description="When true, activate this config and deactivate others",
    )


class TenantEmailConfigResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    from_email: str
    credential_hint: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class TenantEmailConfigListResponse(BaseModel):
    items: list[TenantEmailConfigResponse]
    available_providers: list[str] = Field(
        default_factory=lambda: [p.value for p in EmailProviderType]
    )
    using_platform_default: bool = False
    platform_provider: str | None = None
    platform_from_email: str | None = None


class EmailConfigTestRequest(BaseModel):
    to_email: EmailStr


class EmailConfigTestResponse(BaseModel):
    success: bool
    error: str | None = None
