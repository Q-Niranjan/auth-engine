import uuid
from datetime import datetime

from pydantic import BaseModel


class IntrospectRequest(BaseModel):
    """
    Request body for token introspection.
    Sent by tenants (or any service) to validate a user's access token.
    """

    token: str
    tenant_id: uuid.UUID | None = None


class TokenPermissions(BaseModel):
    """Permissions the user has — optionally scoped to a tenant."""

    tenant_id: uuid.UUID | None = None
    permissions: list[str]


class IntrospectResponse(BaseModel):
    """
    Returned to the calling service (YourComapny etc.).

    active=True  → token is valid, user info is included
    active=False → token is expired, revoked, or invalid — all other fields will be None
    """

    active: bool

    # Only populated when active=True
    user_id: uuid.UUID | None = None
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    avatar_url: str | None = None
    is_email_verified: bool | None = None

    # Auth metadata
    auth_strategy: str | None = None  # "email_password" | "google" | "github" etc.
    issued_at: datetime | None = None
    expires_at: datetime | None = None

    # Permissions — scoped to tenant_id if provided in request
    permissions: list[str] = []

    # Tenant memberships
    tenant_ids: list[uuid.UUID] = []
