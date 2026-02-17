import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.email_config import TenantEmailConfigORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class TenantEmailConfigRepository(PostgresRepository[TenantEmailConfigORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(TenantEmailConfigORM, session)

    async def get_by_tenant_id(self, tenant_id: uuid.UUID) -> TenantEmailConfigORM | None:
        query = select(self.model).where(self.model.tenant_id == tenant_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
