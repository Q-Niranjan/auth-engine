import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.core.exceptions import AuthenticationError, InvalidTokenError
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.schemas.mfa import (
    MFAConfirmRequest,
    MFAConfirmResponse,
    MFADisableRequest,
    MFAEnrollResponse,
)
from auth_engine.services.totp_service import TOTPService

router = APIRouter()


@router.post("/enroll", response_model=MFAEnrollResponse)
async def enroll_mfa(
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> MFAEnrollResponse:
    svc = TOTPService(db, redis_conn)
    try:
        result = await svc.begin_enrollment(current_user)
        await db.commit()
        return MFAEnrollResponse(**result)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc


@router.post("/verify", response_model=MFAConfirmResponse)
async def verify_mfa_enrollment(
    body: MFAConfirmRequest,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> MFAConfirmResponse:
    svc = TOTPService(db, redis_conn)
    try:
        result = await svc.confirm_enrollment(current_user, body.code)
        await db.commit()
        return MFAConfirmResponse(**result)
    except (AuthenticationError, InvalidTokenError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc


@router.delete("/disable", response_model=MFAConfirmResponse)
async def disable_mfa(
    body: MFADisableRequest,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> MFAConfirmResponse:
    svc = TOTPService(db, redis_conn)
    try:
        result = await svc.disable_mfa(current_user, body.code)
        await db.commit()
        return MFAConfirmResponse(**result)
    except (AuthenticationError, InvalidTokenError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc


@router.get("/status")
async def mfa_status(
    current_user: UserORM = Depends(get_current_active_user),
) -> dict:
    return {"mfa_enabled": bool(current_user.mfa_enabled)}