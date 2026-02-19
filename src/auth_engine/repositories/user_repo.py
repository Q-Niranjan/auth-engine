import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from auth_engine.models import RoleORM, RolePermissionORM, UserORM, UserRoleORM
from auth_engine.repositories.postgres_repo import PostgresRepository


class UserRepository(PostgresRepository[UserORM]):
    def __init__(self, session: AsyncSession):
        super().__init__(UserORM, session)

    async def get(self, id: uuid.UUID) -> UserORM | None:
        query = (
            select(self.model)
            .where(self.model.id == id)
            .options(
                joinedload(UserORM.roles)
                .joinedload(UserRoleORM.role)
                .joinedload(RoleORM.permissions)
                .joinedload(RolePermissionORM.permission)
            )
        )
        result = await self.session.execute(query)
        return result.unique().scalar_one_or_none()

    async def get_by_email(self, email: str) -> UserORM | None:
        query = (
            select(self.model)
            .where(self.model.email == email)
            .options(
                joinedload(UserORM.roles)
                .joinedload(UserRoleORM.role)
                .joinedload(RoleORM.permissions)
                .joinedload(RolePermissionORM.permission)
            )
        )
        result = await self.session.execute(query)
        return result.unique().scalar_one_or_none()

    async def get_by_username(self, username: str) -> UserORM | None:
        query = (
            select(self.model)
            .where(self.model.username == username)
            .options(
                joinedload(UserORM.roles)
                .joinedload(UserRoleORM.role)
                .joinedload(RoleORM.permissions)
                .joinedload(RolePermissionORM.permission)
            )
        )
        result = await self.session.execute(query)
        return result.unique().scalar_one_or_none()

    async def get_by_phone_number(self, phone_number: str) -> UserORM | None:
        query = (
            select(self.model)
            .where(self.model.phone_number == phone_number)
            .options(
                joinedload(UserORM.roles)
                .joinedload(UserRoleORM.role)
                .joinedload(RoleORM.permissions)
                .joinedload(RolePermissionORM.permission)
            )
        )
        result = await self.session.execute(query)
        return result.unique().scalar_one_or_none()
