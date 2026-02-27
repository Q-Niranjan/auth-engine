import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.api.dependencies.service_api_deps import get_verified_api_key
from auth_engine.core.redis import get_redis
from auth_engine.models.service_api_key import ServiceApiKeyORM
from auth_engine.schemas.introspect import IntrospectRequest, IntrospectResponse
from auth_engine.services.introspect_service import IntrospectService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    summary="Validate a user access token",
    description=(
        "Called by external services (YourComapny, ServiceA, etc.) to validate "
        "a user's access token and retrieve their identity + permissions. "
        "Requires a service API key in the X-API-Key header."
    ),
)
async def introspect_token(
    body: IntrospectRequest,
    api_key: ServiceApiKeyORM = Depends(get_verified_api_key),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> IntrospectResponse:
    """
    Token introspection endpoint.

    External services call this to verify a user token without needing
    the JWT secret. Returns active=False for any invalid/expired/revoked token.

    Example (YourComapny middleware):
        POST /api/v1/auth/introspect
        X-API-Key: ae_sk_...
        { "token": "<user_access_token>", "tenant_id": "<YourComapny_tenant_id>" }
    """
    # If the API key is scoped to a tenant, enforce that scope
    # (key for YourComapny can only see YourComapny tenant data)
    effective_tenant_id = body.tenant_id

    if api_key.tenant_id:
        effective_tenant_id = api_key.tenant_id

    service = IntrospectService(db=db, redis=redis_conn)
    result = await service.introspect(
        token=body.token,
        tenant_id=effective_tenant_id,
    )

    logger.info(
        f"[introspect] service={api_key.service_name} "
        f"active={result.active} "
        f"user={result.user_id}"
    )

    return result
