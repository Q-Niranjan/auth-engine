import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.exceptions import AuthenticationError, InvalidTokenError
from auth_engine.core.redis import get_redis
from auth_engine.schemas.mfa import MFACompleteRequest
from auth_engine.schemas.user import UserLoginResponse, UserResponse
from auth_engine.services.totp_service import TOTPService

router = APIRouter()


@router.post("/complete", response_model=UserLoginResponse)
async def complete_mfa(
    body: MFACompleteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> UserLoginResponse:
    svc = TOTPService(db, redis_conn)
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    try:
        tokens = await svc.complete_mfa(
            mfa_pending_token=body.mfa_pending_token,
            code=body.code,
            ip_address=ip,
            user_agent=ua,
        )
    except InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.message) from exc
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.message) from exc

    return UserLoginResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type=tokens.get("token_type", "bearer"),
        expires_in=tokens.get("expires_in", 1800),
        user=UserResponse.model_validate(tokens["user"]),
    )