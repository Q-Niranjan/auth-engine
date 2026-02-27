import uuid

import redis.asyncio as redis
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_audit_service, get_db
from auth_engine.api.dependencies.rbac import require_permission
from auth_engine.core.config import settings
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import (
    PasswordResetConfirm,
    PasswordResetRequest,
    SetPassword,
    TokenRefresh,
    TokenRequest,
    UserCreate,
    UserLogin,
    UserLoginResponse,
    UserResponse,
)
from auth_engine.services.audit_service import AuditService
from auth_engine.services.auth_service import AuthService
from auth_engine.services.session_service import SessionService

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> UserResponse:
    """
    Public registration API.
    """
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)
    try:
        user = await auth_service.register_user(user_in)
        return UserResponse.model_validate(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/login", response_model=UserLoginResponse)
async def login(
    request: Request,
    login_data: UserLogin,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
    audit_service: AuditService = Depends(get_audit_service),
) -> UserLoginResponse:
    user_repo = UserRepository(db)
    auth_service = AuthService(user_repo)
    session_service = SessionService(redis_conn)

    try:
        user = await auth_service.authenticate_user(login_data)

        # Create a session
        session_id = await session_service.create_session(
            user_id=user.id,
            expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        tokens = auth_service.create_tokens(user, session_id=session_id)

        # Audit Log: Successful Login
        background_tasks.add_task(
            audit_service.log,
            action="LOGIN_SUCCESS",
            resource="Auth",
            resource_id=str(user.id),
            actor_id=user.id,
            metadata={"email": user.email},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        return UserLoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
            user=UserResponse.model_validate(tokens["user"]),
        )
    except ValueError as e:
        # Audit Log: Failed Login
        background_tasks.add_task(
            audit_service.log,
            action="LOGIN_FAILED",
            resource="Auth",
            metadata={"email": login_data.email, "error": str(e)},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            status="failure",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: UserORM = Depends(get_current_active_user),
    redis_conn: redis.Redis = Depends(get_redis),
    audit_service: AuditService = Depends(get_audit_service),
) -> None:
    """
    Log out the current user by deleting all their sessions.
    """
    session_service = SessionService(redis_conn)
    await session_service.delete_all_sessions(current_user.id)

    # Audit Log: Logout
    background_tasks.add_task(
        audit_service.log,
        action="LOGOUT",
        resource="Auth",
        resource_id=str(current_user.id),
        actor_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return None


@router.post("/refresh", response_model=UserLoginResponse)
async def refresh_token(
    refresh_data: TokenRefresh,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> UserLoginResponse:
    """
    Refresh access token using refresh token.
    """
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    try:
        tokens = await auth_service.refresh_tokens(refresh_data.refresh_token)
        return UserLoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
            user=UserResponse.model_validate(tokens["user"]),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    reset_data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)
    await auth_service.initiate_password_reset(reset_data.email, reset_data.tenant_id)
    return {"message": "If the email exists, a reset link will be sent."}


@router.get("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def validate_password_reset(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    user_repo = UserRepository(db)
    auth_service = AuthService(user_repo)
    try:
        await auth_service.validate_password_reset_token(token)
        return {"message": "Token is valid. Please POST your new password to confirm the reset."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def confirm_password_reset(
    confirm_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    if confirm_data.new_password != confirm_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
        )

    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)
    try:
        await auth_service.confirm_password_reset(confirm_data.token, confirm_data.new_password)
        return {"message": "Password reset successfully"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/set-password", status_code=status.HTTP_200_OK)
async def set_password(
    password_data: SetPassword,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    """
    Allow an authenticated OAuth user with no password to set their first password.
    """
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
        )

    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    try:
        await auth_service.set_password_for_oauth_user(current_user, password_data.new_password)
        return {
            "message": "Password set successfully. You can now login with your email and password."
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("/verify-email")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Verify user email with token.
    """
    user_repo = UserRepository(db)
    auth_service = AuthService(user_repo)
    try:
        await auth_service.verify_email(token)
        return {"message": "Email verified successfully"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/verify-phone")
async def verify_phone(
    user_id: uuid.UUID,
    otp: str,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    """
    Verify user phone with OTP.
    """
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)
    try:
        success = await auth_service.verify_phone(user_id, otp)
        if success:
            return {"message": "Phone verified successfully"}
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP"
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/request-token", status_code=status.HTTP_202_ACCEPTED)
async def request_action_token(
    request_data: TokenRequest,
    db: AsyncSession = Depends(get_db),
    redis_conn: redis.Redis = Depends(get_redis),
    current_user: UserORM = Depends(require_permission("auth.tokens.request")),
) -> dict[str, str]:
    """
    Generalized endpoint to request a token for various actions (resend verification, etc).
    """
    user_repo = UserRepository(db)
    session_service = SessionService(redis_conn)
    auth_service = AuthService(user_repo, session_service=session_service)

    try:
        await auth_service.request_token(
            email=request_data.email,
            action_type=request_data.action_type,
            tenant_id=request_data.tenant_id,
        )
        return {"message": "If the account exists, the requested action has been initiated."}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
