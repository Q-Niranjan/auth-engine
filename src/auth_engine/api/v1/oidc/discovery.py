"""
OIDC Discovery Endpoints

Implements the OpenID Connect Discovery specification (RFC 8414).
These endpoints allow any OIDC-compliant client to auto-configure
against AuthEngine as an Identity Provider.

Standard URLs (registered at app root, NOT under /api/v1):
    GET /.well-known/openid-configuration  — discovery document
    GET /.well-known/jwks.json             — public JSON Web Key Set

Both endpoints are also aliased under /api/v1/oidc/ for convenience.
"""

import hashlib
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from auth_engine.core.config import settings
from auth_engine.core.oidc_crypto import OIDC_JWK

logger = logging.getLogger(__name__)

# ── Two routers ───────────────────────────────────────────────────────────────
# router      → mounted at /api/v1/oidc  (aliases, for /docs discoverability)
# well_known  → mounted at /.well-known  (spec-required paths)
router = APIRouter()
well_known_router = APIRouter()


def _get_base_url(request: Request) -> str:
    """
    Derive the public base URL.
    Prefers APP_URL from settings (correct for deployed environments).
    Falls back to the incoming request's base URL for local dev.
    """
    app_url = getattr(settings, "APP_URL", None)
    if app_url and app_url != "http://localhost:8000":
        return app_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _build_discovery_document(request: Request) -> dict:
    """
    Build the OIDC Provider Metadata payload.

    Compliant with:
      - OpenID Connect Discovery 1.0 incorporating errata set 2 (Section 3)
      - RFC 8414  — OAuth 2.0 Authorization Server Metadata

    REQUIRED fields are always present.
    OPTIONAL/RECOMMENDED fields are included where AuthEngine supports them.
    Null/empty fields are omitted per spec §4.2:
      "Claims with zero elements MUST be omitted from the response."
    """
    base = _get_base_url(request)
    api = f"{base}{settings.API_V1_PREFIX}"

    doc: dict = {
        # ── REQUIRED ──────────────────────────────────────────────────────
        # Must be identical to the iss claim in every ID Token issued
        "issuer": settings.JWT_ISSUER,

        # REQUIRED: OAuth 2.0 Authorization Endpoint
        "authorization_endpoint": f"{api}/oidc/authorize",

        # REQUIRED (unless implicit-only): Token Endpoint
        "token_endpoint": f"{api}/oidc/token",

        # REQUIRED: URL of the JWK Set document (signing keys)
        "jwks_uri": f"{base}/.well-known/jwks.json",

        "subject_types_supported": ["public", "pairwise"],

        # REQUIRED: JWS alg values for ID Token signing
        # NOTE: RS256 MUST be listed per spec; we use HS256 (symmetric).
        # Migrate to RS256 for production multi-tenant deployments.
        "id_token_signing_alg_values_supported": ["RS256", settings.JWT_ALGORITHM] if OIDC_JWK else [settings.JWT_ALGORITHM],

        # REQUIRED: response_type values supported
        "response_types_supported": ["code"],

        # ── RECOMMENDED ───────────────────────────────────────────────────

        # RECOMMENDED: UserInfo Endpoint
        "userinfo_endpoint": f"{api}/oidc/userinfo",

        # RECOMMENDED: OAuth 2.0 scopes (MUST include "openid")
        "scopes_supported": ["openid", "profile", "email"],

        # RECOMMENDED: Claim names the OP may supply values for
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time",
            "nonce", "email", "email_verified",
            "name", "given_name", "family_name",
            "picture", "updated_at",
        ],

        # ── OPTIONAL ──────────────────────────────────────────────────────

        # response_mode values supported
        "response_modes_supported": ["query"],

        # Grant types (default is ["authorization_code","implicit"] when omitted)
        "grant_types_supported": ["authorization_code", "refresh_token"],

        # Token Endpoint client authentication methods.
        # Spec options: client_secret_post | client_secret_basic |
        #               client_secret_jwt  | private_key_jwt
        # Default when omitted: client_secret_basic
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ],

        # PKCE — only S256 supported ("plain" is NOT recommended by spec)
        "code_challenge_methods_supported": ["S256"],

        # UserInfo returns plain JSON (not a signed JWT), alg = "none"
        "userinfo_signing_alg_values_supported": ["RS256", "none"] if OIDC_JWK else ["none"],

        # Session termination endpoint
        "end_session_endpoint": f"{api}/auth/logout",

        # Token introspection (RFC 7662)
        "introspection_endpoint": f"{api}/platform/service-keys/introspect",

        # OP does not support the "claims" request parameter
        "claims_parameter_supported": False,

        # OP does not support JAR (JWT-Secured Authorization Requests)
        "request_parameter_supported": False,

        # OP does not support request_uri parameter
        "request_uri_parameter_supported": False,

        # Human-readable developer documentation
        "service_documentation": f"{base}/docs",

        # Dynamic Client Registration endpoint
        "registration_endpoint": f"{api}/oidc/register",
    }

    # Per spec §4.2: omit keys whose value is None
    return {k: v for k, v in doc.items() if v is not None}


def _build_jwks() -> dict:
    """Build the JWKS document."""
    keys = []
    
    # RS256 Key (Public Key)
    if OIDC_JWK:
        keys.append(OIDC_JWK)
    
    # Stable key ID derived from secret — never exposes the secret itself
    kid = hashlib.sha256(settings.JWT_SECRET_KEY[:8].encode()).hexdigest()[:16]
    keys.append({
        "kty": "oct",               # symmetric key type
        "use": "sig",               # signing usage
        "alg": settings.JWT_ALGORITHM,
        "kid": kid,
        # NOTE: HS256 is symmetric — the raw key is NOT published here.
        # For clients that want local verification, migrate to RS256
        # and return the RSA public key (n, e) instead.
    })
    
    return {"keys": keys}


# ── Shared view functions ─────────────────────────────────────────────────────

async def _openid_configuration_view(request: Request) -> JSONResponse:
    return JSONResponse(
        content=_build_discovery_document(request),
        headers={"Cache-Control": "public, max-age=3600"},
    )


async def _jwks_view(request: Request) -> JSONResponse:
    return JSONResponse(
        content=_build_jwks(),
        headers={"Cache-Control": "public, max-age=3600"},
    )


# ── /.well-known/ routes (spec-required, mounted at app root) ─────────────────

@well_known_router.get(
    "/openid-configuration",
    summary="OIDC Discovery Document",
    description=(
        "Standard OIDC discovery document at /.well-known/openid-configuration. "
        "OIDC clients fetch this once to auto-configure all endpoints and features. "
        "Compliant with RFC 8414."
    ),
    tags=["oidc"],
)
async def well_known_openid_configuration(request: Request) -> JSONResponse:
    return await _openid_configuration_view(request)


@well_known_router.get(
    "/jwks.json",
    summary="JSON Web Key Set",
    description="Public JWKS at /.well-known/jwks.json. Used by clients to verify id_token signatures.",
    tags=["oidc"],
)
async def well_known_jwks(request: Request) -> JSONResponse:
    return await _jwks_view(request)


# ── /oidc/ aliases (mounted under /api/v1/oidc, for /docs visibility) ────────

@router.get(
    "/openid-configuration",
    summary="OIDC Discovery Document (alias)",
    description="Alias for /.well-known/openid-configuration. Prefer the well-known URL.",
    tags=["oidc"],
    include_in_schema=False,
)
async def openid_configuration_alias(request: Request) -> JSONResponse:
    return await _openid_configuration_view(request)


@router.get(
    "/jwks.json",
    summary="JWKS (alias)",
    description="Alias for /.well-known/jwks.json.",
    tags=["oidc"],
    include_in_schema=False,
)
async def jwks_alias(request: Request) -> JSONResponse:
    return await _jwks_view(request)