"""
Pydantic schemas for the tenant selection flow.
"""

import uuid

from pydantic import BaseModel


class SelectTenantRequest(BaseModel):
    """Body for POST /auth/select-tenant"""

    tenant_id: uuid.UUID


class SelectTenantResponse(BaseModel):
    """Response for POST /auth/select-tenant — tenant-scoped JWT."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
