import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.oauth_account import OAuthAccountORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class OAuthAccountRepository(PostgresRepository[OAuthAccountORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(OAuthAccountORM, session)

    async def get_by_provider_and_user_id(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccountORM | None:
        """Find an OAuth account by provider name + provider's user ID."""
        query = select(self.model).where(
            self.model.provider == provider,
            self.model.provider_user_id == provider_user_id,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: uuid.UUID) -> list[OAuthAccountORM]:
        """Get all OAuth accounts linked to a specific AuthEngine user."""
        query = select(self.model).where(self.model.user_id == user_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_by_user_and_provider(
        self, user_id: uuid.UUID, provider: str
    ) -> OAuthAccountORM | None:
        """Check if a user already has a specific provider linked."""
        query = select(self.model).where(
            self.model.user_id == user_id,
            self.model.provider == provider,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
