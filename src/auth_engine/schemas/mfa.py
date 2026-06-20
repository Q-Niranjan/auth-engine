from pydantic import BaseModel, Field


class MFAEnrollResponse(BaseModel):
    provisioning_uri: str
    secret: str
    message: str = "Scan the QR code with your authenticator app, then confirm with /me/mfa/verify"


class MFAConfirmRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class MFAConfirmResponse(BaseModel):
    message: str


class MFADisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class MFAChallengeResponse(BaseModel):
    mfa_pending_token: str
    message: str = "MFA required. Submit your TOTP code to /auth/mfa/complete"


class MFAEnrollmentRequiredResponse(BaseModel):
    mfa_enrollment_token: str
    message: str = "This organization requires MFA. Complete authenticator setup to continue."


class MFAEnrollmentStartRequest(BaseModel):
    mfa_enrollment_token: str


class MFAEnrollmentVerifyRequest(BaseModel):
    mfa_enrollment_token: str
    code: str = Field(..., min_length=6, max_length=6)


class MFACompleteRequest(BaseModel):
    mfa_pending_token: str
    code: str = Field(..., min_length=6, max_length=6)
