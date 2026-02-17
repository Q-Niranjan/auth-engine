import uuid

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.models.role import RoleScope
from auth_engine.models.tenant import TenantType
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.services.audit_service import AuditService
from auth_engine.services.permission_service import PermissionService


class RoleService:
    def __init__(self, user_repo: UserRepository, audit_service: AuditService | None = None):
        self.user_repo = user_repo
        self.audit_service = audit_service

    async def assign_role(
        self, actor: UserORM, target_user_id: uuid.UUID, role_name: str, tenant_id: uuid.UUID
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

        # PROTECT SUPER_ADMIN: System role should remain bootstrap-only
        if target_role.name == "SUPER_ADMIN":
            raise ValueError("SUPER_ADMIN role cannot be assigned manually")

        # Fetch tenant
        tenant = await self.user_repo.session.get(TenantORM, tenant_id)
        if not tenant:
            raise ValueError("Tenant not found")

        # Scope enforcement
        if target_role.scope == RoleScope.PLATFORM and tenant.type != TenantType.PLATFORM:
            raise ValueError("Platform roles can only be assigned in platform tenant")

        if target_role.scope == RoleScope.TENANT and tenant.type == TenantType.PLATFORM:
            raise ValueError("Tenant roles cannot be assigned in platform tenant")

        # 2. Authorization: Check if actor has the required permission for the ACTION
        perm_required = (
            "tenant.roles.assign"
            if target_role.scope == RoleScope.TENANT
            else "platform.roles.assign"
        )
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, perm_required, tenant_id
        ):
            raise ValueError(f"Insufficient permissions: Missing '{perm_required}'")

        # 3. Hierarchy: Check if actor's level allows assigning THIS specific role
        # Find the max level of the actor in the relevant context
        max_actor_level = -1
        for ur in actor.roles:
            if ur.tenant_id == tenant_id or ur.role.scope == RoleScope.PLATFORM:
                if ur.role.level > max_actor_level:
                    max_actor_level = ur.role.level

        if max_actor_level == -1:
            raise ValueError("Insufficient permissions: You have no active roles for this context")

        # RULE: Actor must be STRICTLY higher level than the target role
        if target_role.level >= max_actor_level:
            raise ValueError(
                f"Insufficient level: You cannot assign a role with level {target_role.level} "
                f"(your max level {max_actor_level} must be strictly higher)"
            )

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

        if self.audit_service:
            await self.audit_service.log(
                actor_id=actor.id,
                target_user_id=target_user_id,
                tenant_id=str(tenant_id),
                action="ROLE_ASSIGNED",
                resource="UserRole",
                metadata={
                    "role_name": role_name,
                    "role_level": target_role.level,
                },
            )

    async def remove_role(
        self, actor: UserORM, target_user_id: uuid.UUID, role_name: str, tenant_id: uuid.UUID
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

        # PROTECT SUPER_ADMIN: Cannot be removed manually through this service
        if target_role.name == "SUPER_ADMIN":
            raise ValueError("SUPER_ADMIN role cannot be removed manually")

        # 2. Authorization
        perm_required = (
            "tenant.roles.assign"
            if target_role.scope == RoleScope.TENANT
            else "platform.roles.assign"
        )
        if not await PermissionService.has_permission(
            self.user_repo.session, actor, perm_required, tenant_id
        ):
            raise ValueError(f"Insufficient permissions: Missing '{perm_required}'")

        # 3. Hierarchy
        max_actor_level = -1
        for ur in actor.roles:
            if ur.tenant_id == tenant_id or ur.role.scope == RoleScope.PLATFORM:
                if ur.role.level > max_actor_level:
                    max_actor_level = ur.role.level

        if max_actor_level == -1:
            raise ValueError("Insufficient permissions: You have no active roles for this context")

        # RULE: Actor must be STRICTLY higher level than the target role to remove it
        if target_role.level >= max_actor_level:
            raise ValueError(
                f"Insufficient level: You cannot remove a role with level {target_role.level} "
                f"(your max level {max_actor_level} must be strictly higher)"
            )

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

            if self.audit_service:
                await self.audit_service.log(
                    actor_id=actor.id,
                    target_user_id=target_user_id,
                    tenant_id=str(tenant_id),
                    action="ROLE_REMOVED",
                    resource="UserRole",
                    metadata={"role_name": role_name},
                )
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
        query = select(RoleORM).where(RoleORM.scope != RoleScope.PLATFORM)
        result = await self.user_repo.session.execute(query)
        return list(result.scalars().all())
