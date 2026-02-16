import uuid

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from auth_engine.models import RoleORM, UserORM, UserRoleORM
from auth_engine.repositories.user_repo import UserRepository


class RoleService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def assign_role(
        self, actor: UserORM, target_user_id: uuid.UUID, role_name: str, tenant_id: uuid.UUID | None
    ) -> None:
        """
        Assigns a role to a user based on RBAC hierarchy rules.
        """
        # 1. Verification of the target role
        role_query = select(RoleORM).where(RoleORM.name == role_name)
        result = await self.user_repo.session.execute(role_query)
        target_role = result.scalar_one_or_none()

        if not target_role:
            raise ValueError(f"Role '{role_name}' does not exist")

        # 2. Check Hierarchy Rules
        ROLE_ASSIGNMENT_HIERARCHY = {
            "SUPER_ADMIN": [
                "SUPER_ADMIN",
                "PLATFORM_ADMIN",
                "TENANT_OWNER",
                "TENANT_ADMIN",
                "TENANT_MANAGER",
                "TENANT_USER",
            ],
            "PLATFORM_ADMIN": ["TENANT_OWNER", "TENANT_ADMIN", "TENANT_MANAGER", "TENANT_USER"],
            "TENANT_OWNER": ["TENANT_ADMIN", "TENANT_MANAGER", "TENANT_USER"],
            "TENANT_ADMIN": ["TENANT_MANAGER", "TENANT_USER"],
            "TENANT_MANAGER": ["TENANT_USER"],
            "TENANT_USER": [],
        }

        # Find the highest role of the actor in the relevant context
        actor_roles = []
        for ur in actor.roles:
            # If assigning a tenant role, actor must have a role in THAT tenant
            # or be a platform admin
            if tenant_id:
                if ur.tenant_id == tenant_id or ur.role.scope == "platform":
                    actor_roles.append(ur.role.name)
            else:
                # Platform level assignment
                if ur.role.scope == "platform":
                    actor_roles.append(ur.role.name)

        if not actor_roles:
            raise ValueError("Insufficient permissions: You have no active roles for this context")

        # Check if any of actor's roles allow assigning target_role
        can_assign = False
        for ar in actor_roles:
            if role_name in ROLE_ASSIGNMENT_HIERARCHY.get(ar, []):
                can_assign = True
                break

        if not can_assign:
            raise ValueError(f"Insufficient permissions: You cannot assign the '{role_name}' role")

        # 3. Create assignment
        # Check if already assigned
        check_query = select(UserRoleORM).where(
            UserRoleORM.user_id == target_user_id,
            UserRoleORM.role_id == target_role.id,
            UserRoleORM.tenant_id == tenant_id,
        )
        existing = await self.user_repo.session.execute(check_query)
        if existing.scalar_one_or_none():
            return  # Already assigned

        new_assignment = UserRoleORM(
            user_id=target_user_id, role_id=target_role.id, tenant_id=tenant_id
        )
        self.user_repo.session.add(new_assignment)
        await self.user_repo.session.commit()

    async def remove_role(
        self, actor: UserORM, target_user_id: uuid.UUID, role_name: str, tenant_id: uuid.UUID | None
    ) -> bool:
        """
        Removes a role from a user based on RBAC hierarchy rules.
        """
        # 1. Verification of the target role
        role_query = select(RoleORM).where(RoleORM.name == role_name)
        result = await self.user_repo.session.execute(role_query)
        target_role = result.scalar_one_or_none()

        if not target_role:
            raise ValueError(f"Role '{role_name}' does not exist")

        # 2. Check Hierarchy Rules (Simplified: if you can assign it, you can remove it)
        ROLE_ASSIGNMENT_HIERARCHY = {
            "SUPER_ADMIN": [
                "SUPER_ADMIN",
                "PLATFORM_ADMIN",
                "TENANT_OWNER",
                "TENANT_ADMIN",
                "TENANT_MANAGER",
                "TENANT_USER",
            ],
            "PLATFORM_ADMIN": ["TENANT_OWNER", "TENANT_ADMIN", "TENANT_MANAGER", "TENANT_USER"],
            "TENANT_OWNER": ["TENANT_ADMIN", "TENANT_MANAGER", "TENANT_USER"],
            "TENANT_ADMIN": ["TENANT_MANAGER", "TENANT_USER"],
            "TENANT_MANAGER": ["TENANT_USER"],
            "TENANT_USER": [],
        }

        actor_roles = []
        for ur in actor.roles:
            if tenant_id:
                if ur.tenant_id == tenant_id or ur.role.scope == "platform":
                    actor_roles.append(ur.role.name)
            else:
                if ur.role.scope == "platform":
                    actor_roles.append(ur.role.name)

        if not actor_roles:
            raise ValueError("Insufficient permissions")

        can_remove = False
        for ar in actor_roles:
            if role_name in ROLE_ASSIGNMENT_HIERARCHY.get(ar, []):
                can_remove = True
                break

        if not can_remove:
            raise ValueError(f"Insufficient permissions to remove '{role_name}'")

        # 3. Perform removal
        delete_query = select(UserRoleORM).where(
            UserRoleORM.user_id == target_user_id,
            UserRoleORM.role_id == target_role.id,
            UserRoleORM.tenant_id == tenant_id,
        )
        result = await self.user_repo.session.execute(delete_query)
        assignment = result.scalar_one_or_none()

        if assignment:
            await self.user_repo.session.delete(assignment)
            await self.user_repo.session.commit()
            return True
        return False

    async def get_user_roles_in_tenant(
        self, user_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[UserRoleORM]:
        query = (
            select(UserRoleORM)
            .where(UserRoleORM.user_id == user_id, UserRoleORM.tenant_id == tenant_id)
            .options(joinedload(UserRoleORM.role))
        )
        result = await self.user_repo.session.execute(query)
        return list(result.scalars().all())

    async def list_tenant_roles(self) -> list[RoleORM]:
        """
        List all roles that can be assigned within a tenant.
        """
        query = select(RoleORM).where(RoleORM.scope != "platform")
        result = await self.user_repo.session.execute(query)
        return list(result.scalars().all())
