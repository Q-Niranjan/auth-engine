import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.api.dependencies.auth_deps import get_current_active_user
from auth_engine.api.dependencies.deps import get_db
from auth_engine.auth_strategies.constants import SUPPORTED_PROVIDERS
from auth_engine.auth_strategies.oauth.factory import get_oauth_strategy
from auth_engine.core.exceptions import AuthenticationError
from auth_engine.core.redis import get_redis
from auth_engine.models import UserORM
from auth_engine.repositories.oauth_repo import OAuthAccountRepository
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.oauth import (
    OAuthAccountResponse,
    OAuthLoginResponse,
)
from auth_engine.services.oauth_service import OAuthService

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_oauth_service(
    db: AsyncSession,
    redis_conn: aioredis.Redis,
) -> OAuthService:
    return OAuthService(
        user_repo=UserRepository(db),
        oauth_repo=OAuthAccountRepository(db),
        redis_conn=redis_conn,
    )


@router.get("/{provider}/login")
async def oauth_login(
    provider: str,
    tenant_id: str | None = Query(default=None, description="Optional tenant context"),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> RedirectResponse:
    """
    Redirect the user to the provider's OAuth consent/login page.

    Usage:
        Frontend opens: GET /api/v1/auth/oauth/google/login?tenant_id=<uuid>
        Browser is redirected to Google login page.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported provider '{provider}'. "
                f"Choose from: {', '.join(SUPPORTED_PROVIDERS)}"
            ),
        )

    try:
        strategy = get_oauth_strategy(provider)
        oauth_service = _get_oauth_service(db, redis_conn)

        state = await oauth_service.generate_state(tenant_id=tenant_id)
        authorization_url = await strategy.get_authorization_url(state=state)

        logger.info(f"[oauth:{provider}] Initiating login, state={state[:8]}...")
        return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)

    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.exception(f"[oauth:{provider}] Failed to initiate login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate OAuth login.",
        ) from e


@router.get("/{provider}/callback", response_model=OAuthLoginResponse)
async def oauth_callback(
    provider: str,
    code: str = Query(..., description="Authorization code from provider"),
    state: str = Query(..., description="CSRF state token"),
    error: str | None = Query(default=None, description="Error from provider (user denied etc.)"),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> OAuthLoginResponse:
    """
    Handle the OAuth callback from the provider.

    The provider redirects here after the user approves (or denies) access.
    We validate state, exchange the code for tokens, resolve the user, and
    return AuthEngine JWTs.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider '{provider}'",
        )
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth login denied: {error}",
        )

    try:
        strategy = get_oauth_strategy(provider)
        oauth_service = _get_oauth_service(db, redis_conn)

        # Validate + consume the state (CSRF protection)
        await oauth_service.validate_and_consume_state(state)

        # Exchange code → provider tokens → user profile
        oauth_profile = await strategy.authenticate({"code": code})

        # Find or create AuthEngine user
        user, oauth_account, is_new_user = await oauth_service.find_or_create_user(oauth_profile)

        await db.commit()
        await db.refresh(user)

        tokens = oauth_service.issue_tokens(user)

        logger.info(f"[oauth:{provider}] User {user.id} authenticated. new_user={is_new_user}")

        return OAuthLoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
            is_new_user=is_new_user,
            provider=provider,  # type:ignore[arg-type]
        )

    except AuthenticationError as e:
        logger.warning(f"[oauth:{provider}] Authentication failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e
    except Exception as e:
        logger.exception(f"[oauth:{provider}] Callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OAuth authentication failed. Please try again.",
        ) from e


@router.get("/{provider}/link")
async def oauth_link_initiate(
    provider: str,
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    redis_conn: aioredis.Redis = Depends(get_redis),
) -> RedirectResponse:
    """
    Allow an already-authenticated user to link an additional OAuth provider.

    Example: User logged in with email/password wants to also enable Google login.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider '{provider}'",
        )

    try:
        oauth_repo = OAuthAccountRepository(db)
        existing = await oauth_repo.get_by_user_and_provider(current_user.id, provider)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Your account is already linked to {provider}.",
            )

        strategy = get_oauth_strategy(provider)
        oauth_service = _get_oauth_service(db, redis_conn)

        state = await oauth_service.generate_state()
        authorization_url = await strategy.get_authorization_url(state=state)

        return RedirectResponse(url=authorization_url, status_code=status.HTTP_302_FOUND)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[oauth:{provider}] Link initiation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate account linking.",
        ) from e


@router.get("/accounts", response_model=list[OAuthAccountResponse])
async def list_oauth_accounts(
    current_user: UserORM = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> list[OAuthAccountResponse]:
    """
    List all OAuth providers linked to the current user's account.
    Useful for the account settings page.
    """
    oauth_repo = OAuthAccountRepository(db)
    accounts = await oauth_repo.get_by_user_id(current_user.id)
    return [OAuthAccountResponse.model_validate(a) for a in accounts]
