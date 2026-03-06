# schemas/tenant_social_provider.py
"""
Pydantic schemas for Tenant Social Provider endpoints.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SocialProviderName(str, Enum):
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    AUTHENGINE = "authengine"  # AuthEngine as OAuth provider


class TenantSocialProviderCreate(BaseModel):
    """Body for POST /tenants/{tenant_id}/social-providers"""

    provider: SocialProviderName
    client_id: str = Field(..., min_length=1)
    client_secret: str = Field(..., min_length=1)
    redirect_uri: str | None = None

    # For the authengine provider, oidc_discovery_url stores the remote base URL
    # e.g. "https://auth.company.com"
    oidc_discovery_url: str | None = None

    @model_validator(mode="after")
    def validate_authengine_base_url(self) -> "TenantSocialProviderCreate":
        if self.provider == SocialProviderName.AUTHENGINE and not self.oidc_discovery_url:
            raise ValueError(
                "oidc_discovery_url is required for the 'authengine' provider. "
                "Set it to the base URL of the remote AuthEngine instance, "
                "e.g. https://auth.company.com"
            )
        return self


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
    client_id: str
    client_secret_prefix: str
    redirect_uri: str | None = None
    oidc_discovery_url: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
