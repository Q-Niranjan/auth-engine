"""
OIDC Token Endpoint

Handles the authorization code → token exchange.
This is the server-side step in the OIDC Authorization Code flow,
called by your app's backend (not the browser) after the user
is redirected back from AuthEngine's /authorize page.

Endpoint:
    POST /oidc/token

Flow:
    1. User clicks "Login with AuthEngine" on YourApp
    2. YourApp redirects to GET /oidc/authorize
    3. User logs in on AuthEngine
    4. AuthEngine redirects back to YourApp with ?code=...
    5. YourApp backend calls POST /oidc/token with the code
    6. AuthEngine returns { access_token, id_token, refresh_token }
    7. YourApp fetches user profile from GET /oidc/userinfo
"""

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.responses import JSONResponse
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.config import settings
from auth_engine.core.redis import get_redis
from auth_engine.core.security import token_manager
from auth_engine.repositories.user_repo import UserRepository

logger = logging.getLogger(__name__)
router = APIRouter()

# ── PKCE helpers ─────────────────────────────────────────────────────────────


def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """
    Verify PKCE S256 code challenge.
    code_challenge == BASE64URL(SHA256(code_verifier))
    """
    import base64

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


# ── ID Token builder ──────────────────────────────────────────────────────────


def _build_id_token(
    user_id: str,
    email: str,
    given_name: str | None,
    family_name: str | None,
    picture: str | None,
    email_verified: bool,
    client_id: str,
    nonce: str | None = None,
) -> str:
    """
    Build a signed OIDC id_token JWT.

    id_token differs from access_token:
    - aud = client_id (not authengine-api)
    - contains user profile claims directly
    - shorter TTL (10 min)
    - includes nonce for replay protection if provided
    """
    now = datetime.now(UTC)
    claims = {
        # ── Required OIDC claims ──────────────────────────────────────────
        "iss": settings.JWT_ISSUER,
        "sub": user_id,
        "aud": client_id,
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "iat": int(now.timestamp()),
        "auth_time": int(now.timestamp()),
        # ── Profile claims ────────────────────────────────────────────────
        "email": email,
        "email_verified": email_verified,
        "given_name": given_name,
        "family_name": family_name,
        "picture": picture,
    }

    if nonce:
        claims["nonce"] = nonce

    # Remove None profile claims
    claims = {k: v for k, v in claims.items() if v is not None}

    try:
        from auth_engine.core.oidc_crypto import OIDC_RSA_PRIVATE_KEY

        if OIDC_RSA_PRIVATE_KEY:
            # Use RS256 if RSA keys are configured
            headers = {"kid": "rsa1"}
            return jwt.encode(claims, OIDC_RSA_PRIVATE_KEY, algorithm="RS256", headers=headers)
    except ImportError:
        pass

    # Fallback to HS256
    kid = hashlib.sha256(settings.JWT_SECRET_KEY[:8].encode()).hexdigest()[:16]
    headers = {"kid": kid}
    return jwt.encode(
        claims, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM, headers=headers
    )


# ── Token endpoint ────────────────────────────────────────────────────────────


@router.post(
    "/token",
    summary="OIDC Token Exchange",
    description=(
        "Exchanges an authorization code for access_token, id_token, and refresh_token. "
        "Called by your app's backend after the user is redirected back from /oidc/authorize. "
        "Supports PKCE (S256) for public clients."
    ),
    tags=["oidc"],
)
async def token_exchange(
    # Standard OAuth2 token request form fields
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    client_assertion_type: Annotated[str | None, Form()] = None,
    client_assertion: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,  # PKCE
    refresh_token: Annotated[str | None, Form()] = None,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> JSONResponse:
    from sqlalchemy import select

    from auth_engine.core.oidc_crypto import get_pairwise_sub
    from auth_engine.models.oidc_client import OIDCClientORM

    """
    OIDC Token endpoint — authorization_code and refresh_token grant types.

    Authorization Code Flow:
        POST /api/v1/oidc/token
        Content-Type: application/x-www-form-urlencoded

        grant_type=authorization_code
        &code=<code from /authorize redirect>
        &redirect_uri=https://yourapp.com/callback
        &client_id=yourapp
        &code_verifier=<PKCE verifier>

    Refresh Token Flow:
        grant_type=refresh_token
        &refresh_token=<refresh_token>
        &client_id=yourapp
    """

    # ── Client Authentication ───────────────────────────────────────────────
    # If client_id is requested, find it
    client = None
    if client_id:
        result = await db.execute(select(OIDCClientORM).filter_by(client_id=client_id))
        client = result.scalar_one_or_none()

        if client:
            auth_method = client.token_endpoint_auth_method

            if auth_method == "client_secret_post" or auth_method == "client_secret_basic":
                if client_secret != client.client_secret:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_client",
                            "error_description": "Invalid client secret",
                        },
                    )
            elif auth_method == "private_key_jwt":
                if (
                    client_assertion_type
                    != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    or not client_assertion
                ):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_client",
                            "error_description": "client_assertion required for private_key_jwt",
                        },
                    )
                import urllib.request

                from jose import jwt as jose_jwt

                if not client.jwks_uri:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail={
                            "error": "invalid_client",
                            "error_description": "jwks_uri is missing",
                        },
                    )
                try:
                    # In production this would cache the JWKS or hit the URL
                    # For demo purposes we just attempt to decode and let it verify via JWKS.
                    # Normally you fetch the JWKS from client.jwks_uri and verify signature.
                    jwks_resp = urllib.request.urlopen(client.jwks_uri)
                    jwks = __import__("json").loads(jwks_resp.read())
                    jose_jwt.decode(
                        client_assertion,
                        jwks,
                        algorithms=["RS256"],
                        audience="http://localhost:8000/api/v1/oidc/token",
                        issuer=client_id,
                    )
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_client",
                            "error_description": f"JWT signature failed: {str(e)}",
                        },
                    ) from e

    # ── authorization_code grant ──────────────────────────────────────────
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_request", "error_description": "code is required"},
            )

        # Retrieve code payload from Redis
        code_key = f"oidc:code:{code}"
        raw = await redis_conn.get(code_key)
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Code expired or invalid"},
            )

        # Consume immediately — authorization codes are single-use
        await redis_conn.delete(code_key)

        try:
            code_data: dict = __import__("json").loads(raw)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Malformed code payload"},
            ) from e

        # Validate redirect_uri matches what was used at /authorize
        if redirect_uri and code_data.get("redirect_uri") != redirect_uri:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            )

        # Validate client_id
        if client_id and code_data.get("client_id") != client_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_client", "error_description": "client_id mismatch"},
            )

        # PKCE verification — required for public clients
        stored_challenge = code_data.get("code_challenge")
        if stored_challenge:
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_request",
                        "error_description": "code_verifier required",
                    },
                )
            if not _verify_pkce(code_verifier, stored_challenge):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "PKCE verification failed",
                    },
                )

        # Load user
        user_repo = UserRepository(db)
        try:
            user_uuid = uuid.UUID(code_data["user_id"])
        except (KeyError, ValueError) as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "Invalid user in code"},
            ) from err

        user = await user_repo.get(user_uuid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "User not found"},
            )

        # Issue tokens and record session in Redis
        from auth_engine.services.session_service import SessionService

        session_service = SessionService(redis_conn)
        session_id = await session_service.create_session(
            user_id=user.id,
            expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        )
        # Calculate sub to return
        returned_sub = str(user.id)
        if client and client.subject_type == "pairwise":
            sector_id = (
                client.sector_identifier_uri
                or code_data.get("redirect_uri", "")
                or "default_sector"
            )
            returned_sub = get_pairwise_sub(sector_id, returned_sub)

        tokens = token_manager.create_access_token(
            data={
                "sub": str(user.id),
                "oidc_sub": returned_sub,  # Passing the pairwise or public OIDC sub for userinfo
                "client_id": client.client_id if client else (client_id or ""),
                "email": str(user.email),
                "sid": session_id,
                "type": "access",
            }
        )
        refresh = token_manager.create_refresh_token(
            data={"sub": str(user.id), "sid": session_id, "type": "refresh"}
        )

        id_token = _build_id_token(
            user_id=returned_sub,
            email=str(user.email),
            given_name=user.first_name,
            family_name=user.last_name,
            picture=user.avatar_url,
            email_verified=user.is_email_verified,
            client_id=code_data.get("client_id", ""),
            nonce=code_data.get("nonce"),
        )

        logger.info(f"[oidc/token] Issued tokens for user={user.id} client={client_id}")

        return JSONResponse(
            content={
                "access_token": tokens,
                "token_type": "Bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "refresh_token": refresh,
                "id_token": id_token,
                "subject_type": client.subject_type if client else "public",
                "scope": "openid profile email",
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    # ── refresh_token grant ───────────────────────────────────────────────
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_request",
                    "error_description": "refresh_token is required",
                },
            )

        try:
            payload = token_manager.verify_refresh_token(refresh_token)
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired refresh token",
                },
            ) from err

        user_id_str = payload.get("sub")

        user_repo = UserRepository(db)
        user = await user_repo.get(uuid.UUID(user_id_str))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_grant", "error_description": "User not found"},
            )

        from auth_engine.services.session_service import SessionService

        session_service = SessionService(redis_conn)
        session_id_val = str(payload.get("sid")) if payload.get("sid") else None

        # If old session is gone or wasn't provided, create a new valid one
        if not session_id_val or not await session_service.is_session_active(
            user.id, session_id_val
        ):
            session_id_val = await session_service.create_session(
                user_id=user.id,
                expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            )

        # Calculate sub to return
        returned_sub = str(user.id)
        if client and client.subject_type == "pairwise":
            sector_id = client.sector_identifier_uri or "default_sector"
            returned_sub = get_pairwise_sub(sector_id, returned_sub)

        new_access = token_manager.create_access_token(
            data={
                "sub": str(user.id),
                "oidc_sub": returned_sub,
                "client_id": client.client_id if client else (client_id or ""),
                "email": str(user.email),
                "sid": session_id_val,
                "type": "access",
            }
        )

        return JSONResponse(
            content={
                "access_token": new_access,
                "token_type": "Bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    # ── unsupported grant type ────────────────────────────────────────────
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unsupported_grant_type",
                "error_description": f"grant_type '{grant_type}' is not supported",
            },
        )
