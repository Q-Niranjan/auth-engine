import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.service_api_key import ServiceApiKeyORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class ServiceApiKeyRepository(PostgresRepository[ServiceApiKeyORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(ServiceApiKeyORM, session)

    async def get_by_key_hash(self, key_hash: str) -> ServiceApiKeyORM | None:
        """Look up an active, non-expired key by its SHA-256 hash."""
        now = datetime.now(UTC)
        query = select(self.model).where(
            self.model.key_hash == key_hash,
            self.model.is_active == True,  # noqa: E712
        )
        result = await self.session.execute(query)
        key = result.scalar_one_or_none()

        # Check expiry in Python (handles None expires_at cleanly)
        if key and key.expires_at and key.expires_at < now:
            return None

        return key

    async def touch_last_used(self, key_id: uuid.UUID) -> None:
        """Update last_used_at timestamp — called after every successful introspect."""
        await self.update(key_id, {"last_used_at": datetime.now(UTC)})

    async def list_by_tenant(self, tenant_id: uuid.UUID) -> list[ServiceApiKeyORM]:
        query = select(self.model).where(self.model.tenant_id == tenant_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())
