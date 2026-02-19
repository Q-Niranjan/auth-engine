import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

OAuthProvider = Literal["google", "github", "microsoft"]


class OAuthCallbackRequest(BaseModel):
    """Query params received in the OAuth callback from the provider."""

    code: str
    state: str


class OAuthLoginInitResponse(BaseModel):
    """Returned when the frontend requests an OAuth login URL."""

    authorization_url: str
    state: str
    provider: OAuthProvider


class OAuthLoginResponse(BaseModel):
    """Returned after a successful OAuth login/registration."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    is_new_user: bool  # True if account was just created, False if existing user logged in
    provider: OAuthProvider


class OAuthAccountResponse(BaseModel):
    """Details of a linked OAuth account (for /me/oauth-accounts)."""

    id: uuid.UUID
    provider: str
    provider_email: str | None
    provider_name: str | None
    provider_avatar_url: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class OAuthAccountLinkResponse(BaseModel):
    """Response when successfully linking a new OAuth provider to existing account."""

    message: str
    provider: str
    provider_email: str | None
