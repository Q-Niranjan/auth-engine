import secrets
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_engine.api.dependencies.deps import get_db
from auth_engine.models.oidc_client import OIDCClientORM
from auth_engine.schemas.oidc_client import ClientRegistrationRequest, ClientRegistrationResponse

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post(
    "/register",
    response_model=ClientRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Dynamic Client Registration",
    description="Implements RFC 7591 Dynamic Client Registration. No initial access token required for testing (open registration).",
    tags=["oidc"],
)
async def register_client(
    req: ClientRegistrationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new OIDC client dynamically.
    """
    
    # Basic validation
    valid_auth_methods = ["client_secret_basic", "client_secret_post", "private_key_jwt"]
    auth_method = req.token_endpoint_auth_method or "client_secret_basic"
    if auth_method not in valid_auth_methods:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_client_metadata", "error_description": "Unsupported token_endpoint_auth_method"}
        )

    if auth_method == "private_key_jwt" and not req.jwks_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_client_metadata", "error_description": "jwks_uri is required for private_key_jwt"}
        )

    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(64) if auth_method in ["client_secret_basic", "client_secret_post"] else None
    
    # Store client in DB
    client = OIDCClientORM(
        client_id=client_id,
        client_secret=client_secret,
        client_name=req.client_name,
        redirect_uris=req.redirect_uris,
        response_types=req.response_types,
        grant_types=req.grant_types,
        token_endpoint_auth_method=auth_method,
        jwks_uri=req.jwks_uri,
        subject_type=req.subject_type,
        sector_identifier_uri=req.sector_identifier_uri,
    )
    
    db.add(client)
    await db.commit()
    await db.refresh(client)
    
    logger.info(f"[oidc/register] Registered new client: {client_id}")

    return ClientRegistrationResponse(
        client_id=client_id,
        client_secret=client_secret,
        client_id_issued_at=int(client.created_at.timestamp()),
        client_secret_expires_at=0, # 0 means never expires
        client_name=client.client_name,
        redirect_uris=client.redirect_uris,
        response_types=client.response_types,
        grant_types=client.grant_types,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        jwks_uri=client.jwks_uri,
        subject_type=client.subject_type,
        sector_identifier_uri=client.sector_identifier_uri
    )
