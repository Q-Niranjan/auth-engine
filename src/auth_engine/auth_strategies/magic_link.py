# auth_strategies/magic_link.py
"""
Magic Link Authentication Strategy
===================================
Flow:
  1. User submits email  →  POST /auth/magic-link/request
  2. Service generates a signed JWT (purpose=magic_link, TTL=15 min)
     and stores a one-time-use flag in Redis under magic:jti:{jti}
  3. Link is emailed:  GET /auth/magic-link/verify?token=<jwt>
  4. MagicLinkStrategy.authenticate() validates signature, expiry, one-time flag
  5. Flag is consumed (deleted from Redis) — link is dead from this point on
  6. AuthEngine issues normal access + refresh tokens
"""

import logging
import uuid
from datetime import timedelta
from typing import Any

import redis.asyncio as aioredis

from auth_engine.auth_strategies.base import TokenBasedStrategy
from auth_engine.auth_strategies.constants import MAGIC_LINK_PREFIX, MAGIC_LINK_TTL_SECONDS
from auth_engine.core.exceptions import AuthenticationError, InvalidTokenError, TokenExpiredError
from auth_engine.core.security import token_manager

logger = logging.getLogger(__name__)


class MagicLinkStrategy(TokenBasedStrategy):
    """
    Passwordless authentication via a signed, short-lived, one-time-use URL.

    Inherits from TokenBasedStrategy (requires_password → False).

    Responsibilities:
      - generate_token(email)  : produce a JWT + set Redis one-time flag
      - authenticate()         : validate JWT + consume Redis flag → return user profile
      - validate()             : pure JWT verification (no Redis check; used by introspect)
    """

    def __init__(self, user_repository: Any, redis_client: aioredis.Redis):
        super().__init__("magic_link")
        self.user_repo = user_repository
        self.redis = redis_client

    def generate_token(self, email: str) -> str:
        """
        Generate a signed JWT for magic-link authentication.

        Payload extras:
          - type     : "magic_link"   (distinguishes from access/refresh/reset tokens)
          - jti      : unique UUID    (used as the Redis one-time-use key)
          - email    : recipient's email (redundant with sub but convenient)

        The caller is responsible for storing the one-time flag in Redis
        via set_one_time_flag() immediately after calling this method so that
        the flag is present before the email is dispatched.
        """
        jti = str(uuid.uuid4())
        token = token_manager.create_access_token(
            data={
                "sub": email,
                "email": email,
                "type": "magic_link",
                "jti": jti,
                "strategy": self.name,
            },
            expires_delta=timedelta(seconds=MAGIC_LINK_TTL_SECONDS),
        )
        return token

    async def set_one_time_flag(self, jti: str) -> None:
        """
        Write the one-time-use flag into Redis.

        Key   : magic:jti:<jti>
        Value : "pending"
        TTL   : MAGIC_LINK_TTL_SECONDS (auto-expires with the token)
        """
        key = f"{MAGIC_LINK_PREFIX}{jti}"
        await self.redis.setex(key, MAGIC_LINK_TTL_SECONDS, "pending")
        logger.debug(f"[MagicLink] Redis flag set: {key}")

    async def authenticate(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """
        Validate a magic-link token and exchange it for a user record.

        Credentials dict must contain:
          - token : str  — the raw JWT from the URL query-param

        Raises:
          - AuthenticationError  if token is missing / malformed
          - TokenExpiredError    if JWT exp claim has passed
          - InvalidTokenError    if signature is bad, wrong type, or already used

        Returns a dict consumed by the auth endpoint to create session tokens.
        """
        token: str | None = credentials.get("token")
        if not token:
            raise AuthenticationError("Magic link token is required")

        try:
            payload = token_manager.decode_token(token)
        except ValueError as exc:
            msg = str(exc).lower()
            if "expired" in msg:
                raise TokenExpiredError(
                    "Magic link has expired. Please request a new one."
                ) from exc
            raise InvalidTokenError(f"Invalid magic link token: {exc}") from exc

        if payload.get("type") != "magic_link":
            raise InvalidTokenError("Token type is not a magic link token")

        email: str | None = payload.get("email") or payload.get("sub")
        jti: str | None = payload.get("jti")

        if not email or not jti:
            raise InvalidTokenError("Magic link token is missing required claims")

        redis_key = f"{MAGIC_LINK_PREFIX}{jti}"
        flag = await self.redis.get(redis_key)

        if flag is None:
            raise InvalidTokenError(
                "Magic link has already been used or is invalid. Please request a new one."
            )

        deleted = await self.redis.delete(redis_key)
        if deleted == 0:
            raise InvalidTokenError("Magic link was just used. Please request a new one.")

        logger.info(f"[MagicLink] Token consumed for email={email}, jti={jti}")

        user = await self.user_repo.get_by_email(email)
        if not user:
            raise AuthenticationError("No account found for this magic link.")

        user_data = {
            "user": user,
            "email": email,
            "strategy": self.name,
            "jti": jti,
        }
        return await self.post_authenticate(user_data)

    async def validate(self, token: str) -> dict[str, Any]:
        """
        Stateless JWT validation — used by /auth/introspect.

        Does NOT check the Redis flag (the token may be consumed but the
        introspect caller just wants to know if the JWT itself is structurally
        valid and unexpired).
        """
        try:
            payload = token_manager.decode_token(token)
        except ValueError as exc:
            raise InvalidTokenError(f"Invalid magic link token: {exc}") from exc

        if payload.get("type") != "magic_link":
            raise InvalidTokenError("Token is not a magic link token")

        return payload

    def get_strategy_metadata(self) -> dict[str, Any]:
        base = super().get_strategy_metadata()
        base.update(
            {
                "ttl_seconds": MAGIC_LINK_TTL_SECONDS,
                "one_time_use": True,
                "delivery": "email",
            }
        )
        return base
