"""
WebAuthn / Passkey Schemas

Covers registration (attestation) and authentication (assertion) ceremonies,
as well as user-facing credential management responses.
"""

from datetime import datetime

from pydantic import BaseModel, Field

# ── Registration ─────────────────────────────────────────────────────────────


class WebAuthnRegisterBeginResponse(BaseModel):
    """Returned to the browser to kick off navigator.credentials.create()."""

    options: dict  # PublicKeyCredentialCreationOptions (JSON-serialisable)
    message: str = "Pass these options to navigator.credentials.create()"


class WebAuthnRegisterCompleteRequest(BaseModel):
    """Browser posts the attestation result back after user gesture."""

    credential: dict = Field(..., description="PublicKeyCredential JSON from the browser")
    device_name: str = Field(default="My Passkey", max_length=255)


class WebAuthnRegisterCompleteResponse(BaseModel):
    credential_id: str
    device_name: str
    message: str = "Passkey registered successfully"


# ── Authentication ────────────────────────────────────────────────────────────


class WebAuthnAuthBeginRequest(BaseModel):
    """
    The browser (or client) supplies the email so we can scope the challenge
    to known credentials for that user. Email is optional for discoverable
    credentials (resident keys); omit to get a platform-wide assertion request.
    """

    email: str | None = Field(default=None, description="User email — omit for resident-key flow")


class WebAuthnAuthBeginResponse(BaseModel):
    """Returned to the browser to kick off navigator.credentials.get()."""

    options: dict  # PublicKeyCredentialRequestOptions (JSON-serialisable)
    message: str = "Pass these options to navigator.credentials.get()"


class WebAuthnAuthCompleteRequest(BaseModel):
    """Browser posts the assertion result back after user gesture."""

    credential: dict = Field(..., description="PublicKeyCredential JSON from the browser")


# ── Credential management ─────────────────────────────────────────────────────


class WebAuthnCredentialResponse(BaseModel):
    """A single registered credential as shown in the user's settings."""

    id: str
    device_name: str
    aaguid: str
    created_at: datetime
    last_used_at: datetime | None

    model_config = {"from_attributes": True}


class WebAuthnCredentialListResponse(BaseModel):
    credentials: list[WebAuthnCredentialResponse]
    total: int
