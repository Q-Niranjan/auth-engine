import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.permission_service import PermissionService


class TenantService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_tenant(
        self, name: str, user_id: uuid.UUID, description: str | None = None
    ) -> TenantORM:
        tenant = TenantORM(name=name, description=description)
        self.user_repo.session.add(tenant)
        await self.user_repo.session.flush()

        # Automatically assign TENANT_OWNER
        role_query = select(RoleORM).where(RoleORM.name == "TENANT_OWNER")
        role_result = await self.user_repo.session.execute(role_query)
        owner_role = role_result.scalar_one_or_none()

        if owner_role:
            user_role = UserRoleORM(user_id=user_id, role_id=owner_role.id, tenant_id=tenant.id)
            self.user_repo.session.add(user_role)

        await self.user_repo.session.commit()
        await self.user_repo.session.refresh(tenant)
        return tenant

    async def list_my_tenants(self, user_id: uuid.UUID) -> list[TenantORM]:
        query = (
            select(TenantORM)
            .join(UserRoleORM, UserRoleORM.tenant_id == TenantORM.id)
            .where(UserRoleORM.user_id == user_id)
            .distinct()
        )
        result = await self.user_repo.session.execute(query)
        return list(result.scalars().all())

    async def get_tenant(
        self, tenant_id: uuid.UUID, actor: UserORM | None = None
    ) -> TenantORM | None:
        if actor and not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.view", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.view'")

        query = select(TenantORM).where(TenantORM.id == tenant_id)
        result = await self.user_repo.session.execute(query)
        return result.scalar_one_or_none()

    async def update_tenant(
        self, tenant_id: uuid.UUID, actor: UserORM, **kwargs: Any
    ) -> TenantORM | None:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.update", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.update'")

        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return None

        for key, value in kwargs.items():
            if value is not None and hasattr(tenant, key):
                setattr(tenant, key, value)

        await self.user_repo.session.commit()
        await self.user_repo.session.refresh(tenant)
        return tenant

    async def delete_tenant(self, tenant_id: uuid.UUID, actor: UserORM) -> bool:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.delete", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.delete'")

        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False

        await self.user_repo.session.delete(tenant)
        await self.user_repo.session.commit()
        return True

    async def list_tenant_users(self, tenant_id: uuid.UUID, actor: UserORM) -> list[UserORM]:
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.view", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.view'")

        query = (
            select(UserORM)
            .join(UserRoleORM, UserRoleORM.user_id == UserORM.id)
            .where(UserRoleORM.tenant_id == tenant_id)
            .options(joinedload(UserORM.roles).joinedload(UserRoleORM.role))
            .distinct()
        )
        result = await self.user_repo.session.execute(query)
        return list(result.unique().scalars().all())

    async def remove_user_from_tenant(
        self, tenant_id: uuid.UUID, user_id: uuid.UUID, actor: UserORM
    ) -> bool:
        """
        Removes all role mappings for a user in a specific tenant (not deleting user globally).
        """
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, "tenant.users.manage", tenant_id
        ):
            raise ValueError("Insufficient permissions: Missing 'tenant.users.manage'")

        query = select(UserRoleORM).where(
            UserRoleORM.tenant_id == tenant_id, UserRoleORM.user_id == user_id
        )
        result = await self.user_repo.session.execute(query)
        mappings = result.scalars().all()

        if not mappings:
            return False

        for mapping in mappings:
            await self.user_repo.session.delete(mapping)

        await self.user_repo.session.commit()
        return True
