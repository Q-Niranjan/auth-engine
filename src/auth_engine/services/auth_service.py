import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from auth_engine.core.config import settings
from auth_engine.core.security import pwd_context, security, token_manager
from auth_engine.external_services.email import EmailServiceResolver
from auth_engine.external_services.sms import SMSServiceResolver
from auth_engine.models import UserORM
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository
from auth_engine.repositories.sms_config_repo import TenantSMSConfigRepository
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.user import UserCreate, UserLogin, UserStatus

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, user_repo: UserRepository, session_service: Any = None):
        self.user_repo = user_repo
        self.session_service = session_service

        self.email_config_repo = TenantEmailConfigRepository(user_repo.session)
        self.email_resolver = EmailServiceResolver(self.email_config_repo)

        self.sms_config_repo = TenantSMSConfigRepository(user_repo.session)
        self.sms_resolver = SMSServiceResolver(self.sms_config_repo)

    async def register_user(self, user_in: UserCreate) -> UserORM:
        existing_user = await self.user_repo.get_by_email(user_in.email)
        if existing_user:
            raise ValueError("User with this email already exists")

        if user_in.username:
            existing_user = await self.user_repo.get_by_username(user_in.username)
            if existing_user:
                raise ValueError("Username already taken")

        if user_in.phone_number:
            existing_user = await self.user_repo.get_by_phone_number(user_in.phone_number)
            if existing_user:
                raise ValueError("User with this phone number already exists")

        password_hash = security.hash_password(user_in.password)

        user_data = {
            "id": str(uuid.uuid4()),
            "email": user_in.email,
            "username": user_in.username,
            "phone_number": user_in.phone_number,
            "password_hash": password_hash,
            "first_name": user_in.first_name,
            "last_name": user_in.last_name,
            "status": UserStatus.PENDING_VERIFICATION,
            "auth_strategies": [user_in.auth_strategy.value],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        user = await self.user_repo.create(user_data)
        await self.user_repo.session.commit()

        await self.initiate_verifications(user)

        return user

    async def initiate_verifications(self, user: UserORM, tenant_id: str | None = None) -> None:
        if user.email:
            await self.initiate_email_verification(user, tenant_id=tenant_id)

        if user.phone_number:
            await self.initiate_phone_verification(user, tenant_id=tenant_id)

    async def authenticate_user(self, login_data: UserLogin) -> UserORM:
        user = await self.user_repo.get_by_email(login_data.email)
        if not user:
            raise ValueError("Invalid email or password")

        if not user.password_hash or not security.verify_password(
            login_data.password, str(user.password_hash)
        ):
            # TODO: Increment failed login attempts
            raise ValueError("Invalid email or password")

        if user.status != UserStatus.ACTIVE:
            raise ValueError("Account not activated", user.status.value)

        # Update last login
        user.last_login_at = datetime.utcnow()
        await self.user_repo.session.commit()

        return user

    def create_tokens(self, user: UserORM, session_id: str | None = None) -> dict[str, Any]:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        # Prepare roles and permissions for embedding in JWT
        roles = []
        permissions = set()
        for ur in user.roles:
            role_name = ur.role.name
            roles.append(
                {"name": role_name, "tenant_id": str(ur.tenant_id) if ur.tenant_id else None}
            )
            for rp in ur.role.permissions:
                permissions.add(rp.permission.name)

        user_data = {
            "sub": str(user.id),
            "email": str(user.email),
            "roles": roles,
            "permissions": list(permissions),
            "sid": session_id,
        }

        access_token = token_manager.create_access_token(
            data=user_data, expires_delta=access_token_expires
        )
        refresh_token = token_manager.create_refresh_token(
            data=user_data, expires_delta=refresh_token_expires
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user,
        }

    async def initiate_password_reset(
        self, email: str, tenant_id: uuid.UUID | str | None = None
    ) -> None:
        user = await self.user_repo.get_by_email(email)
        if not user:
            return

        if not user.password_hash:
            provider = (user.auth_strategies[0] if user.auth_strategies else "social").capitalize()
            raise ValueError(
                f"This account uses {provider} login. \
                Please sign in with {provider} or set a password."
            )

        reset_token = self.generate_action_token(
            user, token_type="password_reset", expires_delta=timedelta(hours=1)
        )
        target_tenant = tenant_id if tenant_id else "default"

        try:
            email_service = await self.email_resolver.resolve(target_tenant)

            app_url = getattr(settings, "APP_URL", "http://localhost:8000")
            api_prefix = settings.API_V1_PREFIX
            reset_link = f"{app_url}{api_prefix}/auth/password-reset/confirm?token={reset_token}"

            subject = "Password Reset Request"
            html_content = f"""
            <html>
                <body>
                    <h1>Password Reset</h1>
                    <p>Hello {user.first_name or 'User'},</p>
                    <p>You requested a password reset. Click the 
                    link below to reset your password:</p>
                    <p><a href="{reset_link}">Reset Password</a></p>
                    <p>This link expires in 1 hour.</p>
                    <p>If you did not request this, please ignore this email.</p>
                </body>
            </html>
            """

            await email_service.send_email([email], subject, html_content)
            logger.info(f"Password reset email sent to {email} via {type(email_service).__name__}")

        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")

    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        """
        Validate refresh token and issue new access/refresh tokens.
        """
        payload = token_manager.verify_refresh_token(refresh_token)
        user_id = payload.get("sub")
        sid = payload.get("sid")

        if not user_id or not sid:
            raise ValueError("Invalid refresh token: missing user_id or sid")

        # Check if the session is still active in Redis
        if not await self.session_service.is_session_active(user_id, sid):
            raise ValueError("Session has been revoked or expired")

        user = await self.user_repo.get(uuid.UUID(user_id))
        if not user:
            raise ValueError("User not found")

        if user.status != UserStatus.ACTIVE:
            raise ValueError(f"User account is {user.status}")

        return self.create_tokens(user, session_id=sid)

    async def verify_email(self, token: str) -> UserORM:
        """
        Verify email using a token.
        """
        payload = token_manager.decode_token(token)
        if payload.get("type") != "email_verification":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token: sub missing")

        user = await self.user_repo.get(uuid.UUID(user_id))
        if not user:
            raise ValueError("User not found")

        user.is_email_verified = True
        if user.status == UserStatus.PENDING_VERIFICATION:
            user.status = UserStatus.ACTIVE

        await self.user_repo.session.commit()
        return user

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        """
        Confirm password reset using a token.
        """
        payload = token_manager.decode_token(token)
        if payload.get("type") != "password_reset":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token: sub missing")

        user = await self.user_repo.get(uuid.UUID(user_id))
        if not user:
            raise ValueError("User not found")

        user.password_hash = security.hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        await self.user_repo.session.commit()
        logger.info(f"Password reset successful for user {user.email}")

    async def set_password_for_oauth_user(self, user: UserORM, new_password: str) -> None:
        """
        Allow an authenticated OAuth user (with no password) to set a password.
        """
        if user.password_hash:
            raise ValueError(
                "Password already exists for this account. Use update-password instead."
            )

        user.password_hash = security.hash_password(new_password)
        user.password_changed_at = datetime.utcnow()

        # Update auth strategies to include email_password
        strategies = list(user.auth_strategies or [])
        if "email_password" not in strategies:
            strategies.append("email_password")
            user.auth_strategies = strategies

        await self.user_repo.session.commit()
        logger.info(f"Password set for OAuth user {user.id}")

    async def validate_password_reset_token(self, token: str) -> uuid.UUID:
        """
        Validate a password reset token and return the user_id.
        """
        payload = token_manager.decode_token(token)
        if payload.get("type") != "password_reset":
            raise ValueError("Invalid token type")

        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token: sub missing")

        return uuid.UUID(user_id)

    async def verify_phone(self, user_id: uuid.UUID, otp: str) -> bool:
        """
        Verify phone OTP.
        """
        if not self.session_service or not hasattr(self.session_service, "redis"):
            raise RuntimeError("SessionService/Redis not configured for OTP verification")

        key = f"otp:phone:{user_id}"
        cached_otp = await self.session_service.redis.get(key)

        if not cached_otp or not pwd_context.verify(otp, cached_otp):
            return False

        user = await self.user_repo.get(user_id)
        if not user:
            return False

        user.is_phone_verified = True
        # Optionally update status if it was pending
        if user.status == UserStatus.PENDING_VERIFICATION and user.is_email_verified:
            user.status = UserStatus.ACTIVE

        await self.user_repo.session.commit()
        await self.session_service.redis.delete(key)
        return True

    def generate_action_token(
        self,
        user: UserORM,
        token_type: str,
        expires_delta: timedelta | None = None,
        extra_data: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate a signed JWT for specific actions (email verification, password reset, etc).
        """
        if not expires_delta:
            expires_delta = timedelta(hours=24)

        token_payload = {
            "sub": str(user.id),
            "email": str(user.email),
            "type": token_type,
        }
        if extra_data:
            token_payload.update(extra_data)

        return token_manager.create_access_token(token_payload, expires_delta=expires_delta)

    async def initiate_email_verification(
        self, user: UserORM, tenant_id: str | None = None
    ) -> None:
        """
        Send an email verification link to the user.
        """
        token = self.generate_action_token(user, token_type="email_verification")

        target_tenant = tenant_id if tenant_id else "default"

        try:
            email_service = await self.email_resolver.resolve(target_tenant)
            app_url = getattr(settings, "APP_URL", "http://localhost:8000")
            api_prefix = settings.API_V1_PREFIX
            verify_link = f"{app_url}{api_prefix}/auth/verify-email?token={token}"

            subject = "Verify Your Email"
            html_content = f"""
            <html>
                <body>
                    <h1>Email Verification</h1>
                    <p>Hello {user.first_name or 'User'},</p>
                    <p>Please click the link below to verify your email address:</p>
                    <p><a href="{verify_link}">Verify Email</a></p>
                    <p>This link expires in 24 hours.</p>
                </body>
            </html>
            """
            await email_service.send_email([str(user.email)], subject, html_content)
            logger.info(f"Verification email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send verification email: {e}")

    async def initiate_phone_verification(self, user: UserORM, tenant_id: str | None = None) -> str:
        if not user.phone_number:
            raise ValueError("User has no phone number")

        redis = self.session_service.redis

        cooldown_key = f"otp:cooldown:{user.id}"
        if await redis.exists(cooldown_key):
            raise Exception("Please wait before requesting another OTP")

        otp = security.generate_otp(6)
        hashed_otp = pwd_context.hash(otp)

        otp_key = f"otp:phone:{user.id}"
        await redis.setex(otp_key, 600, hashed_otp)
        await redis.setex(cooldown_key, 60, "1")

        target_tenant = tenant_id if tenant_id else "default"

        try:
            sms_service = await self.sms_resolver.resolve(target_tenant)

            # Basic E.164 formatting for common 10-digit numbers missing a prefix
            phone = str(user.phone_number)
            if len(phone) == 10 and not phone.startswith("+"):
                # Defaulting to +91 as per your logs, but better to enforce it via UI
                phone = f"+91{phone}"
            elif not phone.startswith("+"):
                logger.warning(
                    f"Phone number {phone} might be invalid for Twilio (missing + prefix)"
                )

            message = f"Your verification code is: {otp}. It expires in 10 minutes."

            success = await sms_service.send_sms(phone, message)
            if success:
                logger.info(f"Verification SMS sent successfully to {phone}")
            else:
                logger.error(f"Twilio failed to send SMS to {phone}")

        except Exception as e:
            logger.error(f"Failed to send verification SMS: {e}")

        return "OTP sent successfully"

    async def request_token(
        self, email: str, action_type: str, tenant_id: uuid.UUID | None = None
    ) -> None:
        """
        Generalized token request handler.
        """
        user = await self.user_repo.get_by_email(email)
        if not user:
            # Silent return to avoid user enumeration
            return

        if action_type == "email_verification":
            await self.initiate_email_verification(
                user, tenant_id=str(tenant_id) if tenant_id else None
            )
        elif action_type == "phone_verification":
            await self.initiate_phone_verification(
                user, tenant_id=str(tenant_id) if tenant_id else None
            )
        elif action_type == "password_reset":
            await self.initiate_password_reset(email, tenant_id=tenant_id)
        else:
            raise ValueError(f"Unsupported action type: {action_type}")
