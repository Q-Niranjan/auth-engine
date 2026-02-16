from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.user import UserORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class UserRepository(PostgresRepository[UserORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserORM, session)

    async def get_by_email(self, email: str) -> UserORM | None:
        query = select(self.model).where(self.model.email == email)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> UserORM | None:
        query = select(self.model).where(self.model.username == username)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
