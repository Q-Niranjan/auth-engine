"""
OAuthService — the heart of social login.

Responsibilities:
    1. Receive normalized profile data from a provider strategy
    2. Find existing user by OAuth account OR by email (account linking)
    3. Create new user if neither exists
    4. Upsert the oauth_accounts record (update tokens on re-login)
    5. Issue AuthEngine JWT tokens
    6. Handle the state/CSRF token lifecycle via Redis
"""

import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis

from auth_engine.core.config import settings
from auth_engine.core.exceptions import AuthenticationError
from auth_engine.core.security import token_manager
from auth_engine.models import UserORM
from auth_engine.models.oauth_account import OAuthAccountORM
from auth_engine.repositories.oauth_repo import OAuthAccountRepository
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserStatus

logger = logging.getLogger(__name__)

# Redis key prefix for OAuth state tokens
_STATE_PREFIX = "oauth:state:"
_STATE_TTL_SECONDS = 600  # 10 minutes — more than enough for a login flow


class OAuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        oauth_repo: OAuthAccountRepository,
        redis_conn: aioredis.Redis,
    ):
        self.user_repo = user_repo
        self.oauth_repo = oauth_repo
        self.redis = redis_conn

    # -------------------------------------------------------------------------
    # State / CSRF management
    # -------------------------------------------------------------------------

    async def generate_state(self, tenant_id: str | None = None) -> str:
        """
        Generate a cryptographically secure state token and store it in Redis.

        The state is used to prevent CSRF attacks on the OAuth callback.
        Optionally encodes tenant_id so the callback knows which tenant
        the login is for.

        Returns:
            The state string to embed in the authorization URL.
        """
        raw_state = secrets.token_urlsafe(32)

        # Store in Redis with TTL
        redis_key = f"{_STATE_PREFIX}{raw_state}"
        value = tenant_id or "none"
        await self.redis.setex(redis_key, _STATE_TTL_SECONDS, value)

        return raw_state

    async def validate_and_consume_state(self, state: str) -> str | None:
        """
        Validate a state token from the callback and remove it (one-time use).

        Returns:
            The tenant_id that was encoded, or None if no tenant context.

        Raises:
            AuthenticationError: If state is invalid or expired.
        """
        # State may have tenant_id appended: "{raw_state}:{tenant_id}"
        parts = state.split(":", 1)
        raw_state = parts[0]

        redis_key = f"{_STATE_PREFIX}{raw_state}"
        stored_value = await self.redis.get(redis_key)

        if not stored_value:
            raise AuthenticationError(
                "Invalid or expired OAuth state token. Please try logging in again."
            )

        # Consume (delete) immediately — one-time use
        await self.redis.delete(redis_key)

        stored_str = stored_value.decode() if isinstance(stored_value, bytes) else stored_value
        tenant_id = stored_str if stored_str != "none" else None

        # If tenant_id was appended to state in URL, prefer that
        if len(parts) > 1 and parts[1]:
            tenant_id = parts[1]

        return tenant_id

    # -------------------------------------------------------------------------
    # Core: find or create user from OAuth profile
    # -------------------------------------------------------------------------

    async def find_or_create_user(
        self, oauth_profile: dict[str, Any]
    ) -> tuple[UserORM, OAuthAccountORM, bool]:
        """
        The central method that handles all user identity resolution.

        Strategy:
            1. Look up existing oauth_account by (provider, provider_user_id)
               → User exists and has used this provider before → just update tokens
            2. Look up user by email
               → User exists but hasn't linked this provider → link it now
            3. Neither found → create new user + oauth_account

        Args:
            oauth_profile: Normalized profile dict from BaseOAuthStrategy.authenticate()

        Returns:
            Tuple of (user, oauth_account, is_new_user)
        """
        provider = oauth_profile["provider"]
        provider_user_id = oauth_profile["provider_user_id"]
        email = oauth_profile["email"]
        provider_tokens = oauth_profile.get("provider_tokens", {})

        # --- Case 1: Known OAuth account ---
        existing_oauth = await self.oauth_repo.get_by_provider_and_user_id(
            provider, provider_user_id
        )

        if existing_oauth:
            # Update provider tokens (they may have rotated)
            await self._update_oauth_tokens(existing_oauth, provider_tokens, oauth_profile)
            user = await self.user_repo.get(existing_oauth.user_id)
            if not user:
                raise AuthenticationError("User account not found for linked OAuth account.")
            logger.info(f"[oauth:{provider}] Existing user {user.id} logged in")
            return user, existing_oauth, False

        # --- Case 2: User exists by email — link the new provider ---
        existing_user = await self.user_repo.get_by_email(email)

        if existing_user:
            oauth_account = await self._create_oauth_account(
                user_id=existing_user.id,
                oauth_profile=oauth_profile,
                provider_tokens=provider_tokens,
            )
            # Append this strategy to user's auth_strategies list
            await self._add_auth_strategy(existing_user, provider)
            logger.info(
                f"[oauth:{provider}] Linked new provider to existing user {existing_user.id}"
            )
            return existing_user, oauth_account, False

        # --- Case 3: Brand new user ---
        new_user = await self._create_user_from_oauth(oauth_profile)
        oauth_account = await self._create_oauth_account(
            user_id=new_user.id,
            oauth_profile=oauth_profile,
            provider_tokens=provider_tokens,
        )
        logger.info(f"[oauth:{provider}] Created new user {new_user.id} from {provider} login")
        return new_user, oauth_account, True

    async def _create_user_from_oauth(self, profile: dict[str, Any]) -> UserORM:
        """Create a new AuthEngine user from OAuth profile data."""
        user_data = {
            "id": uuid.uuid4(),
            "email": profile["email"],
            "first_name": profile.get("first_name"),
            "last_name": profile.get("last_name"),
            "avatar_url": profile.get("avatar_url"),
            "password_hash": None,  # OAuth users have no password
            "status": UserStatus.ACTIVE,  # Email already verified by provider
            "is_email_verified": True,
            "is_phone_verified": False,
            "auth_strategies": [profile["provider"]],
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        user = await self.user_repo.create(user_data)
        return user

    async def _create_oauth_account(
        self,
        user_id: uuid.UUID,
        oauth_profile: dict[str, Any],
        provider_tokens: dict[str, Any],
    ) -> OAuthAccountORM:
        """Insert a new oauth_accounts row."""
        expires_at = provider_tokens.get("expires_at")
        if isinstance(expires_at, (int | float)):
            expires_at = datetime.fromtimestamp(float(expires_at), tz=UTC)

        data = {
            "id": uuid.uuid4(),
            "user_id": user_id,
            "provider": oauth_profile["provider"],
            "provider_user_id": oauth_profile["provider_user_id"],
            "access_token": provider_tokens.get("access_token"),
            "refresh_token": provider_tokens.get("refresh_token"),
            "token_expires_at": expires_at,
            "provider_email": oauth_profile.get("email"),
            "provider_avatar_url": oauth_profile.get("avatar_url"),
            "provider_name": oauth_profile.get("provider_name"),
        }
        return await self.oauth_repo.create(data)

    async def _update_oauth_tokens(
        self,
        oauth_account: OAuthAccountORM,
        provider_tokens: dict[str, Any],
        profile: dict[str, Any],
    ) -> None:
        """Refresh stored provider tokens and profile snapshot on re-login."""
        expires_at = provider_tokens.get("expires_at")
        if isinstance(expires_at, (int | float)):
            expires_at = datetime.fromtimestamp(float(expires_at), tz=UTC)

        await self.oauth_repo.update(
            oauth_account.id,
            {
                "access_token": provider_tokens.get("access_token"),
                "refresh_token": provider_tokens.get("refresh_token"),
                "token_expires_at": expires_at,
                "provider_email": profile.get("email"),
                "provider_avatar_url": profile.get("avatar_url"),
                "provider_name": profile.get("provider_name"),
                "updated_at": datetime.now(UTC),
            },
        )

    async def _add_auth_strategy(self, user: UserORM, strategy_name: str) -> None:
        """Append a new strategy name to the user's auth_strategies JSON list."""
        current_strategies: list[str] = user.auth_strategies or []
        if strategy_name not in current_strategies:
            updated = current_strategies + [strategy_name]
            await self.user_repo.update(user.id, {"auth_strategies": updated})

    # -------------------------------------------------------------------------
    # Token issuance
    # -------------------------------------------------------------------------

    def issue_tokens(self, user: UserORM) -> dict[str, Any]:
        """Issue AuthEngine JWT access + refresh tokens for the authenticated user."""
        access_token = token_manager.create_access_token(
            data={
                "sub": str(user.id),
                "email": user.email,
                "strategy": "oauth",
            }
        )
        refresh_token = token_manager.create_refresh_token(
            data={
                "sub": str(user.id),
                "email": user.email,
            }
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }
