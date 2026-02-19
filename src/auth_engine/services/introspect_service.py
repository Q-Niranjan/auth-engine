"""
IntrospectService

Validates an access token on behalf of a calling service (e.g. YourComapny).
Returns the user's identity + permissions if the token is valid.

This is the server-side equivalent of what get_current_user does internally,
but exposed as an API so external services can use it without knowing the JWT secret.
"""

import logging
import uuid
from datetime import UTC, datetime

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.security import token_manager
from auth_engine.models import UserORM
from auth_engine.models.user import UserStatus
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.introspect import IntrospectResponse

logger = logging.getLogger(__name__)


class IntrospectService:
    def __init__(self, db: AsyncSession, redis: aioredis.Redis):
        self.db = db
        self.redis = redis
        self.user_repo = UserRepository(db)

    async def introspect(
        self,
        token: str,
        tenant_id: uuid.UUID | None = None,
    ) -> IntrospectResponse:
        """
        Full token introspection.

        Steps:
            1. Decode and verify JWT signature + expiry
            2. Check token is not blacklisted (logout)
            3. Check session is still alive in Redis
            4. Load user from DB — must be ACTIVE
            5. Collect permissions (scoped to tenant_id if provided)
            6. Return full introspection response

        Returns active=False (never raises) so the calling service
        gets a clean boolean to act on.
        """
        # ── Step 1: Decode JWT ────────────────────────────────────────────
        try:
            payload = token_manager.verify_access_token(token)
        except Exception as e:
            logger.debug(f"[introspect] Token decode failed: {e}")
            return IntrospectResponse(active=False)

        user_id_str: str | None = payload.get("sub")
        if not user_id_str:
            return IntrospectResponse(active=False)

        # ── Step 2: Blacklist check ───────────────────────────────────────
        jti: str | None = payload.get("jti")
        if jti:
            is_blacklisted = await self.redis.exists(f"blacklist:{jti}")
            if is_blacklisted:
                logger.debug(f"[introspect] Token jti={jti} is blacklisted")
                return IntrospectResponse(active=False)

        # ── Step 3: Session check ─────────────────────────────────────────
        session_id: str | None = payload.get("sid")
        if session_id:
            session_key = f"session:{user_id_str}:{session_id}"
            session_exists = await self.redis.exists(session_key)
            if not session_exists:
                logger.debug(f"[introspect] Session {session_id} not found for user {user_id_str}")
                return IntrospectResponse(active=False)

        # ── Step 4: Load user ─────────────────────────────────────────────
        try:
            user_uuid = uuid.UUID(user_id_str)
        except ValueError:
            return IntrospectResponse(active=False)

        user: UserORM | None = await self.user_repo.get(user_uuid)

        if not user:
            return IntrospectResponse(active=False)

        if user.status != UserStatus.ACTIVE:
            logger.debug(f"[introspect] User {user_uuid} is not ACTIVE: {user.status}")
            return IntrospectResponse(active=False)

        # ── Step 5: Collect permissions ───────────────────────────────────
        permissions: list[str] = []
        tenant_ids: list[uuid.UUID] = []

        for user_role in user.roles:
            # Collect tenant memberships
            if user_role.tenant_id and user_role.tenant_id not in tenant_ids:
                tenant_ids.append(user_role.tenant_id)

            # Collect permissions — scoped to requested tenant if provided
            if tenant_id is None or user_role.tenant_id == tenant_id:
                for role_perm in user_role.role.permissions:
                    perm_name = role_perm.permission.name
                    if perm_name not in permissions:
                        permissions.append(perm_name)

        # ── Step 6: Build response ────────────────────────────────────────
        iat = payload.get("iat")
        exp = payload.get("exp")

        return IntrospectResponse(
            active=True,
            user_id=user.id,
            email=str(user.email),
            first_name=user.first_name,
            last_name=user.last_name,
            avatar_url=user.avatar_url,
            is_email_verified=user.is_email_verified,
            auth_strategy=payload.get("strategy"),
            issued_at=datetime.fromtimestamp(iat, tz=UTC) if iat else None,
            expires_at=datetime.fromtimestamp(exp, tz=UTC) if exp else None,
            permissions=permissions,
            tenant_ids=tenant_ids,
        )
