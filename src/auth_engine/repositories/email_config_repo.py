import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.email_config import TenantEmailConfigORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class TenantEmailConfigRepository(PostgresRepository[TenantEmailConfigORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(TenantEmailConfigORM, session)

    async def list_by_tenant_id(self, tenant_id: uuid.UUID) -> list[TenantEmailConfigORM]:
        query = (
            select(self.model)
            .where(self.model.tenant_id == tenant_id)
            .order_by(self.model.is_active.desc(), self.model.from_email)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantEmailConfigORM | None:
        query = select(self.model).where(
            self.model.tenant_id == tenant_id,
            self.model.is_active.is_(True),
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantEmailConfigORM | None:
        return await self.get_active_by_tenant_id(tenant_id)

    async def get_by_id(
        self, tenant_id: uuid.UUID, config_id: uuid.UUID
    ) -> TenantEmailConfigORM | None:
        query = select(self.model).where(
            self.model.tenant_id == tenant_id,
            self.model.id == config_id,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
