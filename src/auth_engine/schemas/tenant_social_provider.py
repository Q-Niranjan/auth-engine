"""
Pydantic schemas for Tenant Social Provider endpoints.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SocialProviderName(str, Enum):
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    AUTHENGINE = "authengine"


class TenantSocialProviderCreate(BaseModel):
    """Body for POST /tenants/{tenant_id}/social-providers"""

    provider: SocialProviderName
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    redirect_uri: str | None = None
    oidc_discovery_url: str | None = None


class TenantSocialProviderUpdate(BaseModel):
    """Body for PUT /tenants/{tenant_id}/social-providers/{provider}"""

    client_id: str | None = None
    client_secret: str | None = None
    redirect_uri: str | None = None
    oidc_discovery_url: str | None = None
    is_active: bool | None = None


class TenantSocialProviderToggle(BaseModel):
    """Body for PATCH /tenants/{tenant_id}/social-providers/{provider}/toggle"""

    is_active: bool


class TenantSocialProviderResponse(BaseModel):
    """Response — never includes raw client_secret."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    client_id: (
        str  # the encrypted value is decrypted only internally; here we show the stored value
    )
    client_secret_prefix: str
    redirect_uri: str | None = None
    oidc_discovery_url: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
