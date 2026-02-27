# services/magic_link_service.py
"""
MagicLinkService
================
Orchestrates the full magic-link lifecycle:

  request_magic_link(email, tenant_id)
    └─ find/validate user
    └─ MagicLinkStrategy.generate_token()
    └─ MagicLinkStrategy.set_one_time_flag()  ← Redis written BEFORE email dispatch
    └─ send email with signed URL

  verify_magic_link(token)
    └─ MagicLinkStrategy.authenticate()       ← validates JWT + consumes Redis flag
    └─ AuthService.create_tokens()            ← returns standard access + refresh JWTs
    └─ SessionService.create_session()        ← registers Redis session
"""

import logging
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.magic_link import MagicLinkStrategy
from auth_engine.core.config import settings
from auth_engine.external_services.email.resolver import EmailServiceResolver
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.auth_service import AuthService
from auth_engine.services.session_service import SessionService

logger = logging.getLogger(__name__)


class MagicLinkService:
    def __init__(
        self,
        db: AsyncSession,
        redis_client: aioredis.Redis,
        email_resolver: EmailServiceResolver,
    ) -> None:
        self.user_repo = UserRepository(db)
        self.redis = redis_client
        self.email_resolver = email_resolver
        self.strategy = MagicLinkStrategy(self.user_repo, redis_client)
        self.session_service = SessionService(redis_client)
        self.auth_service = AuthService(self.user_repo, session_service=self.session_service)

    async def request_magic_link(
        self,
        email: str,
        tenant_id: uuid.UUID | str | None = None,
        ip_address: str | None = None,
    ) -> None:
        """
        Generate a magic link and dispatch it via email.

        Always returns successfully — even if the email is not registered —
        to prevent user enumeration attacks. A warning is logged server-side.

        Security order of operations:
          1. Generate JWT (pure CPU — no I/O)
          2. Decode to extract jti
          3. Write Redis flag (I/O) ← must succeed before email is sent
          4. Send email            ← link is live only after step 3
        """
        user = await self.user_repo.get_by_email(email)
        if not user:
            logger.warning(f"[MagicLink] Link requested for unknown email: {email}")
            # Return silently — do not reveal non-existence to caller
            return

        if user.status not in ("active", "ACTIVE"):
            logger.warning(
                f"[MagicLink] Link requested for inactive account: {email} status={user.status}"
            )
            return

        # ── 1+2. Generate token & extract jti ─────────────────────────
        token = self.strategy.generate_token(email)
        from auth_engine.core.security import token_manager

        payload = token_manager.decode_token(token)
        jti: str = payload["jti"]

        # ── 3. Write Redis one-time flag (before sending email!) ───────
        await self.strategy.set_one_time_flag(jti)
        logger.info(f"[MagicLink] One-time flag written. email={email} jti={jti}")

        # ── 4. Build and send the email ────────────────────────────────
        app_url = getattr(settings, "APP_URL", "http://localhost:8000")
        api_prefix = settings.API_V1_PREFIX
        magic_url = f"{app_url}{api_prefix}/auth/magic-link/verify?token={token}"

        first_name = getattr(user, "first_name", None) or "there"

        html_content = f"""
        <html>
          <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Your Magic Login Link</h2>
            <p>Hi {first_name},</p>
            <p>Click the button below to sign in. This link expires in
               <strong>15 minutes</strong> and can only be used <strong>once</strong>.</p>
            <p style="margin: 32px 0;">
              <a href="{magic_url}"
                 style="background:#4F46E5;color:#fff;padding:14px 28px;
                        border-radius:6px;text-decoration:none;font-weight:bold;">
                Sign In to AuthEngine
              </a>
            </p>
            <p style="color:#888;font-size:13px;">
              If you didn't request this, you can safely ignore this email.
              The link will expire on its own.
            </p>
            <p style="color:#aaa;font-size:11px;word-break:break-all;">
              Or copy this URL into your browser:<br/>{magic_url}
            </p>
          </body>
        </html>
        """

        try:
            target_tenant = tenant_id if tenant_id else "default"
            email_svc = await self.email_resolver.resolve(target_tenant)
            await email_svc.send_email(
                [email],
                "Your Magic Sign-In Link",
                html_content,
            )
            logger.info(f"[MagicLink] Email dispatched to {email}")
        except Exception as exc:
            # If email fails, revoke the Redis flag so the token can't be replayed
            # by someone who intercepts the half-sent message.
            from auth_engine.auth_strategies.magic_link import MAGIC_LINK_PREFIX

            await self.redis.delete(f"{MAGIC_LINK_PREFIX}{jti}")
            logger.error(f"[MagicLink] Email dispatch failed, flag revoked. error={exc}")
            # Re-raise so the API layer can return a 502 (email provider failure)
            raise

    async def verify_magic_link(
        self,
        token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate the magic link token and return AuthEngine session tokens.

        Raises:
          - AuthenticationError / InvalidTokenError / TokenExpiredError
            (propagated from MagicLinkStrategy.authenticate())

        Returns:
          {
            access_token, refresh_token, token_type, expires_in,
            user: UserORM
          }
        """
        # Delegates to strategy — validates JWT + consumes Redis flag
        auth_data = await self.strategy.authenticate({"token": token})
        user: UserORM = auth_data["user"]
        
        if "email_magic_link" not in user.auth_strategies:
            user.auth_strategies.append("email_magic_link")
            await self.user_repo.session.commit()
        
        # Create a tracked session (same as normal login)
        session_id = await self.session_service.create_session(
            user_id=user.id,
            expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            ip_address=ip_address or "unknown",
            user_agent=user_agent or "unknown",
        )

        tokens = self.auth_service.create_tokens(user, session_id=session_id)

        logger.info(
            f"[MagicLink] User authenticated. " f"user_id={user.id} session_id={session_id}"
        )
        return tokens
        
