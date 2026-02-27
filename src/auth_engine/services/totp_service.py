import uuid
from datetime import timedelta
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.constants import MFA_PENDING_PREFIX, MFA_PENDING_TTL_SECONDS
from auth_engine.auth_strategies.totp import TOTPStrategy
from auth_engine.core.config import settings
from auth_engine.core.exceptions import AuthenticationError, InvalidTokenError
from auth_engine.core.security import SecurityUtils, token_manager
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.auth_service import AuthService
from auth_engine.services.session_service import SessionService


class TOTPService:
    def __init__(self, db: AsyncSession, redis_client: aioredis.Redis) -> None:
        self.user_repo = UserRepository(db)
        self.redis = redis_client
        self.strategy = TOTPStrategy()
        self.session_service = SessionService(redis_client)
        self.auth_service = AuthService(self.user_repo, session_service=self.session_service)

    async def begin_enrollment(self, user: UserORM) -> dict[str, str]:
        """Generate secret and return provisioning URI for enrollment."""
        if user.mfa_enabled:
            raise AuthenticationError("MFA is already enabled for this account")

        raw_secret = TOTPStrategy.generate_secret()
        encrypted_secret = SecurityUtils.encrypt_data(raw_secret)

        await self.user_repo.update(
            user.id,
            {
                "mfa_secret": encrypted_secret,
                "mfa_enabled": False,
            },
        )

        provisioning_uri = TOTPStrategy.get_provisioning_uri(
            raw_secret,
            str(user.email),
            issuer=getattr(settings, "APP_NAME", "AuthEngine"),
        )

        return {
            "provisioning_uri": provisioning_uri,
            "secret": raw_secret,
        }

    async def confirm_enrollment(self, user: UserORM, code: str) -> dict[str, str]:
        """Verify the first TOTP code to finalize MFA activation."""
        if user.mfa_enabled:
            raise AuthenticationError("MFA is already enabled")

        if not user.mfa_secret:
            raise AuthenticationError("MFA enrollment not initiated. Call /me/mfa/enroll first.")

        if not user.mfa_secret or not TOTPStrategy.verify_code(user.mfa_secret, code):
            raise InvalidTokenError("Invalid TOTP code. Please check your authenticator app.")

        await self.user_repo.update(user.id, {"mfa_enabled": True})

        return {"message": "MFA enabled successfully"}

    async def disable_mfa(self, user: UserORM, code: str) -> dict[str, str]:
        """Disable MFA for the user after verifying a final code."""
        if not user.mfa_enabled:
            raise AuthenticationError("MFA is not enabled")

        if not user.mfa_secret or not TOTPStrategy.verify_code(user.mfa_secret, code):
            raise InvalidTokenError("Invalid TOTP code")

        await self.user_repo.update(
            user.id,
            {"mfa_enabled": False, "mfa_secret": None},
        )

        return {"message": "MFA disabled successfully"}

    @staticmethod
    def issue_mfa_pending_token(user_id: str) -> str:
        """Issue a short-lived JWT for the pending MFA state."""
        return token_manager.create_access_token(
            data={"sub": user_id, "type": "mfa_pending"},
            expires_delta=timedelta(seconds=MFA_PENDING_TTL_SECONDS),
        )

    async def store_mfa_pending(self, user_id: str, session_context: dict[str, Any]) -> str:
        """Store session context in Redis and return a pending token."""
        token = self.issue_mfa_pending_token(user_id)
        payload = token_manager.decode_token(token)
        jti = payload.get("jti") or str(uuid.uuid4())

        import json

        key = f"{MFA_PENDING_PREFIX}{user_id}"
        await self.redis.setex(
            key, MFA_PENDING_TTL_SECONDS, json.dumps({**session_context, "jti": jti})
        )

        return token

    async def complete_mfa(
        self,
        mfa_pending_token: str,
        code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Validate pending state and TOTP code to issue final session tokens."""
        try:
            payload = token_manager.decode_token(mfa_pending_token)
        except ValueError as exc:
            raise InvalidTokenError("MFA session expired or invalid") from exc

        if payload.get("type") != "mfa_pending":
            raise InvalidTokenError("Invalid token type for MFA completion")

        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError("MFA token missing user identity")

        import json

        key = f"{MFA_PENDING_PREFIX}{user_id}"
        raw = await self.redis.get(key)
        if not raw:
            raise InvalidTokenError("MFA session expired. Please log in again.")

        await self.redis.delete(key)

        user = await self.user_repo.get(uuid.UUID(user_id))
        if not user:
            raise AuthenticationError("User not found")

        if not user.mfa_enabled or not user.mfa_secret:
            raise AuthenticationError("MFA not configured for this account")

        if not user.mfa_secret or not TOTPStrategy.verify_code(user.mfa_secret, code):
            raise InvalidTokenError("Invalid TOTP code")

        session_context = json.loads(raw)
        session_id = await self.session_service.create_session(
            user_id=user.id,
            expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            ip_address=ip_address or session_context.get("ip_address", "unknown"),
            user_agent=user_agent or session_context.get("user_agent", "unknown"),
        )

        return self.auth_service.create_tokens(user, session_id=session_id)
