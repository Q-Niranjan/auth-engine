import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.sms_config import TenantSMSConfigORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class TenantSMSConfigRepository(PostgresRepository[TenantSMSConfigORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(TenantSMSConfigORM, session)

    async def list_by_tenant_id(self, tenant_id: uuid.UUID) -> list[TenantSMSConfigORM]:
        query = (
            select(self.model)
            .where(self.model.tenant_id == tenant_id)
            .order_by(self.model.is_active.desc(), self.model.from_number)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantSMSConfigORM | None:
        query = select(self.model).where(
            self.model.tenant_id == tenant_id,
            self.model.is_active.is_(True),
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantSMSConfigORM | None:
        return await self.get_active_by_tenant_id(tenant_id)

    async def get_by_id(
        self, tenant_id: uuid.UUID, config_id: uuid.UUID
    ) -> TenantSMSConfigORM | None:
        query = select(self.model).where(
            self.model.tenant_id == tenant_id,
            self.model.id == config_id,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
