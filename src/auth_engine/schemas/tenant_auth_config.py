"""
Pydantic schemas for Tenant Auth Configuration endpoints.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# ── Default values ────────────────────────────────────────────────────────────

DEFAULT_ALLOWED_METHODS = [
    "email_password",
    "magic_link",
    "google",
    "github",
    "microsoft",
    "authengine",
]

VALID_AUTH_METHODS = {
    "email_password",
    "magic_link",
    "google",
    "github",
    "microsoft",
    "authengine",
}

DEFAULT_PASSWORD_POLICY = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class PasswordPolicySchema(BaseModel):
    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True


class TenantAuthConfigUpdate(BaseModel):
    """Body for PUT /tenants/{tenant_id}/auth-config"""

    allowed_methods: list[str] | None = None
    mfa_required: bool | None = None
    password_policy: PasswordPolicySchema | None = None
    session_ttl_seconds: int | None = Field(None, ge=300, le=86400)
    allowed_domains: list[str] | None = None
    oidc_client_id: uuid.UUID | None = None


class TenantAuthConfigResponse(BaseModel):
    """Response for GET/PUT /tenants/{tenant_id}/auth-config"""

    id: uuid.UUID
    tenant_id: uuid.UUID
    allowed_methods: list[str]
    mfa_required: bool
    password_policy: dict
    session_ttl_seconds: int
    allowed_domains: list[str]
    oidc_client_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
