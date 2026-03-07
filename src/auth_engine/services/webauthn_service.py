"""
WebAuthnService
===============

Owns all WebAuthn business logic.

Depends on:
  * WebAuthnRepository  — PostgreSQL reads/writes
  * WebAuthnStrategy    — py_webauthn ceremony helpers (pure, stateless)
  * Redis               — challenge storage (TTL-scoped, one-time-use)
  * AuthService         — create_tokens()
  * SessionService      — create_session()
  * UserRepository      — load user by email / id
"""

import base64
import json
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.constants import (
    WEBAUTHN,
    WEBAUTHN_AUTH_PREFIX,
    WEBAUTHN_CHALLENGE_TTL,
    WEBAUTHN_REG_PREFIX,
)
from auth_engine.auth_strategies.webauthn import WebAuthnStrategy
from auth_engine.core.config import settings
from auth_engine.core.exceptions import AuthenticationError, NotFoundError
from auth_engine.models import UserORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.repositories.webauthn_repo import WebAuthnRepository
from auth_engine.services.auth_service import AuthService
from auth_engine.services.session_service import SessionService


class WebAuthnService:
    def __init__(
        self,
        db: AsyncSession,
        redis: aioredis.Redis,
    ) -> None:
        self.db = db
        self.redis = redis
        self.webauthn_repo = WebAuthnRepository(db)
        self.user_repo = UserRepository(db)
        self.session_service = SessionService(redis)
        self.auth_service = AuthService(self.user_repo, self.session_service)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _challenge_reg_key(self, user_id: str) -> str:
        return f"{WEBAUTHN_REG_PREFIX}{user_id}"

    def _challenge_auth_key(self, challenge_hex: str) -> str:
        return f"{WEBAUTHN_AUTH_PREFIX}{challenge_hex}"

    # ── Registration ceremony ──────────────────────────────────────────────────

    async def begin_registration(self, user: UserORM) -> dict:
        """
        Step 1 — generate registration challenge and store it in Redis.

        Returns PublicKeyCredentialCreationOptions for the browser.
        """
        existing_ids = await self.webauthn_repo.get_credential_ids_for_user(user.id)

        display_name = " ".join(filter(None, [user.first_name, user.last_name])) or str(user.email)

        options, challenge = WebAuthnStrategy.generate_registration_options(
            user_id=str(user.id),
            user_email=str(user.email),
            user_display_name=display_name,
            existing_credential_ids=existing_ids,
        )

        # Store raw challenge in Redis (base64url-encoded for safe serialisation)
        await self.redis.setex(
            self._challenge_reg_key(str(user.id)),
            WEBAUTHN_CHALLENGE_TTL,
            base64.urlsafe_b64encode(challenge).decode(),
        )

        return options

    async def complete_registration(
        self,
        user: UserORM,
        credential_json: dict,
        device_name: str = "My Passkey",
    ) -> dict[str, Any]:
        """
        Step 2 — verify attestation, persist credential, update auth_strategies.
        """
        reg_key = self._challenge_reg_key(str(user.id))
        raw = await self.redis.get(reg_key)
        if not raw:
            raise AuthenticationError(
                "Registration challenge expired or not found. Please start over."
            )

        # One-time use — delete before verification to prevent replay
        await self.redis.delete(reg_key)

        challenge = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

        try:
            verified = WebAuthnStrategy.verify_registration_response(
                credential_json=credential_json,
                expected_challenge=challenge,
            )
        except Exception as exc:
            raise AuthenticationError(f"WebAuthn registration verification failed: {exc}") from exc

        # Persist credential
        async with self.db.begin_nested():
            cred = await self.webauthn_repo.create(
                user_id=user.id,
                credential_id=verified["credential_id"],
                public_key=verified["public_key"],
                sign_count=verified["sign_count"],
                aaguid=verified["aaguid"],
                uv_flag=verified["uv_flag"],
                device_name=device_name,
            )

            # Append "webauthn" to auth_strategies if not already present
            strategies: list[str] = list(user.auth_strategies or [])
            if WEBAUTHN not in strategies:
                strategies.append(WEBAUTHN)
                await self.user_repo.update(user.id, {"auth_strategies": strategies})

        await self.db.commit()

        return {
            "credential_id": base64.urlsafe_b64encode(cred.credential_id).rstrip(b"=").decode(),
            "device_name": cred.device_name,
        }

    # ── Authentication ceremony ────────────────────────────────────────────────

    async def begin_authentication(self, email: str | None = None) -> dict:
        """
        Step 1 — generate authentication challenge.

        If *email* is provided, scope allowCredentials to that user's keys
        (targeted assertion). Otherwise, return an empty allowCredentials
        list for discoverable-credential (resident-key) flow.
        """
        allowed_ids: list[bytes] = []

        if email:
            user = await self.user_repo.get_by_email(email)
            if user:
                allowed_ids = await self.webauthn_repo.get_credential_ids_for_user(user.id)

        options, challenge = WebAuthnStrategy.generate_authentication_options(
            allowed_credential_ids=allowed_ids or None,
        )

        # Key by hex(challenge) — the browser sends the same challenge back
        challenge_hex = challenge.hex()
        await self.redis.setex(
            self._challenge_auth_key(challenge_hex),
            WEBAUTHN_CHALLENGE_TTL,
            json.dumps({"challenge_b64": base64.urlsafe_b64encode(challenge).decode()}),
        )

        return options

    async def complete_authentication(
        self,
        credential_json: dict,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """
        Step 2 — verify assertion, update sign count, issue session tokens.
        """
        # Extract challenge from clientDataJSON to look up Redis key
        import base64 as _b64

        client_data_b64 = credential_json.get("response", {}).get("clientDataJSON", "")
        if not client_data_b64:
            raise AuthenticationError("Missing clientDataJSON in credential")

        # clientDataJSON is base64url-encoded JSON
        padding = 4 - len(client_data_b64) % 4
        client_data = json.loads(_b64.urlsafe_b64decode(client_data_b64 + ("=" * (padding % 4))))
        # challenge in clientDataJSON is base64url-encoded
        challenge_b64 = client_data.get("challenge", "")
        padding2 = 4 - len(challenge_b64) % 4
        challenge_bytes = _b64.urlsafe_b64decode(challenge_b64 + ("=" * (padding2 % 4)))
        challenge_hex = challenge_bytes.hex()

        # Look up and consume the challenge from Redis
        auth_key = self._challenge_auth_key(challenge_hex)
        raw = await self.redis.get(auth_key)
        if not raw:
            raise AuthenticationError(
                "Authentication challenge expired or already used. Please try again."
            )
        await self.redis.delete(auth_key)  # one-time use

        stored = json.loads(raw)
        expected_challenge = _b64.urlsafe_b64decode(stored["challenge_b64"] + "==")

        # Identify the credential from the DB
        raw_id_b64 = credential_json.get("rawId") or credential_json.get("id", "")
        padding3 = 4 - len(raw_id_b64) % 4
        raw_id_bytes = _b64.urlsafe_b64decode(raw_id_b64 + ("=" * (padding3 % 4)))

        cred_record = await self.webauthn_repo.get_by_credential_id(raw_id_bytes)
        if not cred_record:
            raise AuthenticationError("Credential not recognised. Please register first.")

        # Verify the assertion
        try:
            result = WebAuthnStrategy.verify_authentication_response(
                credential_json=credential_json,
                expected_challenge=expected_challenge,
                credential_id=cred_record.credential_id,
                public_key=cred_record.public_key,
                current_sign_count=cred_record.sign_count,
            )
        except Exception as exc:
            raise AuthenticationError(f"WebAuthn authentication failed: {exc}") from exc

        # Update sign count (clone detection)
        async with self.db.begin_nested():
            await self.webauthn_repo.update_sign_count(cred_record, result["sign_count"])

        await self.db.commit()

        # Load user and issue tokens
        user = await self.user_repo.get(cred_record.user_id)
        if not user:
            raise AuthenticationError("Associated user not found")

        session_id = await self.session_service.create_session(
            user_id=user.id,
            expires_in_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            ip_address=ip_address or "unknown",
            user_agent=user_agent or "unknown",
        )

        return self.auth_service.create_tokens(user, session_id=session_id)

    # ── Credential management ──────────────────────────────────────────────────

    async def list_credentials(self, user: UserORM) -> list[dict[str, Any]]:
        creds = await self.webauthn_repo.list_for_user(user.id)
        return [
            {
                "id": str(c.id),
                "device_name": c.device_name,
                "aaguid": c.aaguid,
                "created_at": c.created_at,
                "last_used_at": c.last_used_at,
            }
            for c in creds
        ]

    async def delete_credential(self, user: UserORM, credential_uuid: uuid.UUID) -> None:
        cred = await self.webauthn_repo.get_by_id_and_user(credential_uuid, user.id)
        if not cred:
            raise NotFoundError("Credential not found or does not belong to you")

        async with self.db.begin_nested():
            await self.webauthn_repo.delete_credential(cred)

            # If user has no more WebAuthn credentials, strip "webauthn" from strategies
            remaining = await self.webauthn_repo.list_for_user(user.id)
            if not remaining:
                strategies = [s for s in (user.auth_strategies or []) if s != WEBAUTHN]
                await self.user_repo.update(user.id, {"auth_strategies": strategies})

        await self.db.commit()
