from pydantic import BaseModel, Field


class ClientRegistrationRequest(BaseModel):
    client_name: str | None = Field(default=None, description="Human-readable name of the client")
    redirect_uris: list[str] = Field(..., description="Array of redirection URIs")
    response_types: list[str] | None = Field(
        default=["code"], description="Array of OAuth 2.0 response type strings"
    )
    grant_types: list[str] | None = Field(
        default=["authorization_code"], description="Array of OAuth 2.0 grant type strings"
    )
    token_endpoint_auth_method: str | None = Field(
        default="client_secret_basic", description="Requested Client Authentication method"
    )
    jwks_uri: str | None = Field(default=None, description="URL for the Client's JSON Web Key Set")
    subject_type: str | None = Field(
        default="public", description="Subject type requested for responses"
    )
    sector_identifier_uri: str | None = Field(
        default=None,
        description=(
            "URL using the https scheme to be used in calculating "
            "Pseudonymous Identifiers by the OP"
        ),
    )


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int
    client_secret_expires_at: int | None = 0
    client_name: str | None = None
    redirect_uris: list[str]
    response_types: list[str] | None = None
    grant_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    jwks_uri: str | None = None
    subject_type: str | None = None
    sector_identifier_uri: str | None = None
