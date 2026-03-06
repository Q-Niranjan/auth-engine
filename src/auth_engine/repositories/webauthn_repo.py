"""
WebAuthnRepository
==================

All PostgreSQL access for webauthn_credentials.
Services never touch SQLAlchemy directly — they go through this repo.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.webauthn_credential import WebAuthnCredentialORM


class WebAuthnRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── Reads ──────────────────────────────────────────────────────────────────

    async def get_by_credential_id(self, credential_id: bytes) -> WebAuthnCredentialORM | None:
        result = await self.session.execute(
            select(WebAuthnCredentialORM).where(
                WebAuthnCredentialORM.credential_id == credential_id
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: uuid.UUID) -> list[WebAuthnCredentialORM]:
        result = await self.session.execute(
            select(WebAuthnCredentialORM)
            .where(WebAuthnCredentialORM.user_id == user_id)
            .order_by(WebAuthnCredentialORM.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_credential_ids_for_user(self, user_id: uuid.UUID) -> list[bytes]:
        """Return raw credential_id bytes for all credentials belonging to a user."""
        creds = await self.list_for_user(user_id)
        return [c.credential_id for c in creds]

    async def get_by_id_and_user(
        self, credential_id: uuid.UUID, user_id: uuid.UUID
    ) -> WebAuthnCredentialORM | None:
        result = await self.session.execute(
            select(WebAuthnCredentialORM).where(
                WebAuthnCredentialORM.id == credential_id,
                WebAuthnCredentialORM.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    # ── Writes ─────────────────────────────────────────────────────────────────

    async def create(
        self,
        user_id: uuid.UUID,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        aaguid: str,
        uv_flag: bool,
        device_name: str,
    ) -> WebAuthnCredentialORM:
        cred = WebAuthnCredentialORM(
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            aaguid=aaguid,
            uv_flag=uv_flag,
            device_name=device_name,
        )
        self.session.add(cred)
        await self.session.flush()
        await self.session.refresh(cred)
        return cred

    async def update_sign_count(self, credential: WebAuthnCredentialORM, new_count: int) -> None:
        credential.sign_count = new_count
        credential.last_used_at = datetime.now(UTC)
        await self.session.flush()

    async def delete_credential(self, credential: WebAuthnCredentialORM) -> None:
        await self.session.delete(credential)
        await self.session.flush()

    async def delete_all_for_user(self, user_id: uuid.UUID) -> int:
        result = await self.session.execute(
            delete(WebAuthnCredentialORM).where(WebAuthnCredentialORM.user_id == user_id)
        )
        await self.session.flush()
        return result.rowcount  # type: ignore[attr-defined]
