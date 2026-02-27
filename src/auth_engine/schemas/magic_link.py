# schemas/magic_link.py
"""
Pydantic schemas for the Magic Link authentication endpoints.
"""

from pydantic import BaseModel, EmailStr, Field


class MagicLinkRequest(BaseModel):
    """
    Body for POST /auth/magic-link/request
    The only input required from the user is their email address.
    """

    email: EmailStr = Field(
        ...,
        description="Email address to send the magic sign-in link to",
        examples=["user@example.com"],
    )

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
            }
        }


class MagicLinkRequestResponse(BaseModel):
    """
    Response for POST /auth/magic-link/request
    Always returns 202 — even for unknown emails (prevents enumeration).
    """

    message: str = Field(
        default=(
            "If an account exists for that email, a sign-in link has been sent. "
            "It expires in 15 minutes."
        )
    )


class MagicLinkVerifyResponse(BaseModel):
    """
    Response for GET /auth/magic-link/verify
    Same shape as the normal login response so clients can treat them identically.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token lifetime in seconds")
