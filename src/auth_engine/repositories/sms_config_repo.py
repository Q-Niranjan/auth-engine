import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.sms_config import TenantSMSConfigORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class TenantSMSConfigRepository(PostgresRepository[TenantSMSConfigORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(TenantSMSConfigORM, session)

    async def get_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantSMSConfigORM | None:
        query = select(self.model).where(self.model.tenant_id == tenant_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
