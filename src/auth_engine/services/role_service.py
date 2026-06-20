import uuid
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import joinedload

from auth_engine.models import (
    PermissionORM,
    RoleORM,
    RolePermissionORM,
    TenantORM,
    UserORM,
    UserRoleORM,
)
from auth_engine.models.role import (
    PLATFORM_SYSTEM_ROLE_NAMES,
    PROTECTED_TENANT_TEMPLATE_NAMES,
    RoleScope,
)
from auth_engine.models.tenant import TenantType
from auth_engine.repositories.user_repo import UserRepository
from auth_engine.schemas.rbac import (
    RoleCreateRequest,
    RoleUpdateRequest,
    TenantRoleCreateRequest,
)
from auth_engine.services.audit_service import AuditService
from auth_engine.services.permission_service import PermissionService

PLATFORM_SYSTEM_ROLES = PLATFORM_SYSTEM_ROLE_NAMES


class RoleService:
    def __init__(self, user_repo: UserRepository, audit_service: AuditService | None = None):
        self.user_repo = user_repo
        self.audit_service = audit_service

    def _role_load_options(self) -> tuple[Any, ...]:
        return (
            joinedload(RoleORM.permissions).joinedload(RolePermissionORM.permission),
            joinedload(RoleORM.template_role),
        )

    async def _get_tenant_templates(self) -> list[RoleORM]:
        result = await self.user_repo.session.execute(
            select(RoleORM)
            .where(
                RoleORM.is_template.is_(True),
                RoleORM.tenant_id.is_(None),
                RoleORM.scope == RoleScope.TENANT,
            )
            .options(*self._role_load_options())
        )
        return list(result.unique().scalars().all())

    async def list_platform_roles(self) -> list[RoleORM]:
        result = await self.user_repo.session.execute(
            select(RoleORM)
            .where(RoleORM.scope == RoleScope.PLATFORM, RoleORM.tenant_id.is_(None))
            .options(*self._role_load_options())
        )
        return list(result.unique().scalars().all())

    async def list_role_templates(self) -> list[RoleORM]:
        return await self._get_tenant_templates()

    async def list_tenant_roles(self, tenant_id: uuid.UUID) -> list[RoleORM]:
        result = await self.user_repo.session.execute(
            select(RoleORM)
            .where(RoleORM.tenant_id == tenant_id)
            .options(*self._role_load_options())
            .order_by(RoleORM.level.desc(), RoleORM.name)
        )
        return list(result.unique().scalars().all())

    async def get_role_in_tenant(
        self,
        tenant_id: uuid.UUID,
        *,
        role_id: uuid.UUID | None = None,
        role_name: str | None = None,
    ) -> RoleORM | None:
        if role_id:
            result = await self.user_repo.session.execute(
                select(RoleORM)
                .where(RoleORM.id == role_id, RoleORM.tenant_id == tenant_id)
                .options(*self._role_load_options())
            )
            return result.unique().scalar_one_or_none()
        if role_name:
            result = await self.user_repo.session.execute(
                select(RoleORM)
                .where(RoleORM.name == role_name, RoleORM.tenant_id == tenant_id)
                .options(*self._role_load_options())
            )
            return result.unique().scalar_one_or_none()
        return None

    async def clone_templates_for_tenant(self, tenant_id: uuid.UUID) -> dict[str, RoleORM]:
        templates = await self._get_tenant_templates()
        created: dict[str, RoleORM] = {}

        for template in templates:
            existing = await self.user_repo.session.execute(
                select(RoleORM).where(
                    RoleORM.tenant_id == tenant_id,
                    RoleORM.template_role_id == template.id,
                )
            )
            role = existing.scalar_one_or_none()
            if role:
                created[template.name] = role
                continue

            new_role = RoleORM(
                name=template.name,
                description=template.description,
                scope=RoleScope.TENANT,
                level=template.level,
                tenant_id=tenant_id,
                is_template=False,
                template_role_id=template.id,
            )
            new_role.permissions = []
            self.user_repo.session.add(new_role)
            await self.user_repo.session.flush()

            for rp in template.permissions:
                self.user_repo.session.add(
                    RolePermissionORM(role_id=new_role.id, permission_id=rp.permission_id)
                )

            created[template.name] = new_role

        await self.user_repo.session.flush()
        return created

    async def get_tenant_owner_role(self, tenant_id: uuid.UUID) -> RoleORM | None:
        owner_templates = await self.user_repo.session.execute(
            select(RoleORM).where(
                RoleORM.is_template.is_(True),
                RoleORM.tenant_id.is_(None),
                RoleORM.name.in_(PROTECTED_TENANT_TEMPLATE_NAMES),
            )
        )
        owner_template = owner_templates.scalar_one_or_none()
        if not owner_template:
            return None

        result = await self.user_repo.session.execute(
            select(RoleORM).where(
                RoleORM.tenant_id == tenant_id,
                RoleORM.template_role_id == owner_template.id,
            )
        )
        return result.scalar_one_or_none()

    async def clone_template_to_tenant(
        self,
        tenant_id: uuid.UUID,
        template_role_id: uuid.UUID,
        *,
        name: str | None = None,
    ) -> RoleORM:
        template = await self.user_repo.session.get(RoleORM, template_role_id)
        if not template or not template.is_template or template.tenant_id is not None:
            raise ValueError("Template role not found")

        role_name = name or template.name
        existing = await self.user_repo.session.execute(
            select(RoleORM).where(RoleORM.tenant_id == tenant_id, RoleORM.name == role_name)
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Role '{role_name}' already exists in this organization")

        new_role = RoleORM(
            name=role_name,
            description=template.description,
            scope=RoleScope.TENANT,
            level=template.level,
            tenant_id=tenant_id,
            is_template=False,
            template_role_id=template.id,
        )
        new_role.permissions = []
        self.user_repo.session.add(new_role)
        await self.user_repo.session.flush()

        for rp in template.permissions:
            self.user_repo.session.add(
                RolePermissionORM(role_id=new_role.id, permission_id=rp.permission_id)
            )

        await self.user_repo.session.commit()
        return await self._refresh_role(new_role.id)

    async def _refresh_role(self, role_id: uuid.UUID) -> RoleORM:
        result = await self.user_repo.session.execute(
            select(RoleORM).where(RoleORM.id == role_id).options(*self._role_load_options())
        )
        return result.unique().scalar_one()

    async def _validate_tenant_permissions(self, permission_ids: list[uuid.UUID]) -> None:
        for perm_id in permission_ids:
            res = await self.user_repo.session.execute(
                select(PermissionORM).where(PermissionORM.id == perm_id)
            )
            perm = res.scalar_one_or_none()
            if not perm:
                raise ValueError(f"Permission '{perm_id}' not found")
            if not (perm.name.startswith("tenant.") or perm.name.startswith("auth.")):
                raise ValueError(f"Tenant roles cannot contain permission '{perm.name}'")

    async def create_tenant_role(
        self, tenant_id: uuid.UUID, data: TenantRoleCreateRequest
    ) -> RoleORM:
        existing = await self.user_repo.session.execute(
            select(RoleORM).where(RoleORM.tenant_id == tenant_id, RoleORM.name == data.name)
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Role '{data.name}' already exists in this organization")

        new_role = RoleORM(
            name=data.name,
            description=data.description,
            scope=RoleScope.TENANT,
            level=data.level,
            tenant_id=tenant_id,
            is_template=False,
        )
        new_role.permissions = []
        self.user_repo.session.add(new_role)
        await self.user_repo.session.flush()

        await self._validate_tenant_permissions(data.permissions)
        for perm_id in data.permissions:
            self.user_repo.session.add(
                RolePermissionORM(role_id=new_role.id, permission_id=perm_id)
            )

        await self.user_repo.session.commit()
        return await self._refresh_role(new_role.id)

    async def create_role(self, data: RoleCreateRequest) -> RoleORM:
        is_template = data.is_template
        if data.scope == RoleScope.TENANT and is_template is None:
            is_template = True
        if data.scope == RoleScope.PLATFORM:
            is_template = False

        if is_template:
            result = await self.user_repo.session.execute(
                select(RoleORM).where(
                    RoleORM.name == data.name,
                    RoleORM.is_template.is_(True),
                    RoleORM.tenant_id.is_(None),
                )
            )
        else:
            result = await self.user_repo.session.execute(
                select(RoleORM).where(
                    RoleORM.name == data.name,
                    RoleORM.scope == data.scope,
                    RoleORM.tenant_id.is_(None),
                    RoleORM.is_template.is_(False),
                )
            )
        if result.scalar_one_or_none():
            raise ValueError(f"Role '{data.name}' already exists")

        new_role = RoleORM(
            name=data.name,
            description=data.description,
            scope=data.scope,
            level=data.level,
            tenant_id=None,
            is_template=bool(is_template),
        )
        new_role.permissions = []
        self.user_repo.session.add(new_role)
        await self.user_repo.session.flush()

        for perm_id in data.permissions:
            res = await self.user_repo.session.execute(
                select(PermissionORM).where(PermissionORM.id == perm_id)
            )
            perm = res.scalar_one_or_none()
            if not perm:
                raise ValueError(f"Permission '{perm_id}' not found")

            if data.scope == RoleScope.PLATFORM:
                if not (perm.name.startswith("platform.") or perm.name.startswith("auth.")):
                    raise ValueError(f"Platform roles cannot contain permission '{perm.name}'")
            elif data.scope == RoleScope.TENANT:
                if not (perm.name.startswith("tenant.") or perm.name.startswith("auth.")):
                    raise ValueError(f"Tenant roles cannot contain permission '{perm.name}'")

            self.user_repo.session.add(
                RolePermissionORM(role_id=new_role.id, permission_id=perm_id)
            )

        await self.user_repo.session.commit()
        return await self._refresh_role(new_role.id)

    async def update_tenant_role(
        self, tenant_id: uuid.UUID, role_id: uuid.UUID, data: RoleUpdateRequest
    ) -> RoleORM:
        role = await self.get_role_in_tenant(tenant_id, role_id=role_id)
        if not role:
            raise ValueError("Role not found")

        if data.name and data.name != role.name:
            check = await self.user_repo.session.execute(
                select(RoleORM).where(RoleORM.tenant_id == tenant_id, RoleORM.name == data.name)
            )
            if check.scalar_one_or_none():
                raise ValueError(f"Role '{data.name}' already exists in this organization")
            role.name = data.name

        if data.description is not None:
            role.description = data.description
        if data.level is not None:
            role.level = data.level

        if data.permissions is not None:
            await self._validate_tenant_permissions(data.permissions)
            role.permissions = []
            old_perms = await self.user_repo.session.execute(
                select(RolePermissionORM).where(RolePermissionORM.role_id == role.id)
            )
            for old in old_perms.scalars().all():
                await self.user_repo.session.delete(old)
            for perm_id in data.permissions:
                self.user_repo.session.add(
                    RolePermissionORM(role_id=role.id, permission_id=perm_id)
                )

        await self.user_repo.session.commit()
        return await self._refresh_role(role.id)

    async def update_role(self, role_id: uuid.UUID, data: RoleUpdateRequest) -> RoleORM:
        result = await self.user_repo.session.execute(
            select(RoleORM).where(RoleORM.id == role_id).options(joinedload(RoleORM.permissions))
        )
        role = result.unique().scalar_one_or_none()
        if not role:
            raise ValueError("Role not found")

        if role.tenant_id is not None:
            raise ValueError("Use tenant role endpoints to update organization roles")

        if role.name in PLATFORM_SYSTEM_ROLE_NAMES:
            raise ValueError("Cannot modify system roles")

        if data.name is not None and data.name != role.name:
            check = await self.user_repo.session.execute(
                select(RoleORM).where(
                    RoleORM.name == data.name,
                    RoleORM.tenant_id.is_(None),
                    RoleORM.is_template == role.is_template,
                )
            )
            if check.scalar_one_or_none():
                raise ValueError(f"Role '{data.name}' already exists")
            role.name = data.name

        if data.description is not None:
            role.description = data.description
        if data.level is not None:
            role.level = data.level

        if data.permissions is not None:
            role.permissions = []
            old_perms = await self.user_repo.session.execute(
                select(RolePermissionORM).where(RolePermissionORM.role_id == role.id)
            )
            for old in old_perms.scalars().all():
                await self.user_repo.session.delete(old)

            for perm_id in data.permissions:
                res = await self.user_repo.session.execute(
                    select(PermissionORM).where(PermissionORM.id == perm_id)
                )
                perm = res.scalar_one_or_none()
                if not perm:
                    raise ValueError(f"Permission '{perm_id}' not found")

                if role.scope == RoleScope.PLATFORM:
                    if not (perm.name.startswith("platform.") or perm.name.startswith("auth.")):
                        raise ValueError(f"Platform roles cannot contain permission '{perm.name}'")
                elif role.scope == RoleScope.TENANT:
                    if not (perm.name.startswith("tenant.") or perm.name.startswith("auth.")):
                        raise ValueError(f"Tenant roles cannot contain permission '{perm.name}'")

                self.user_repo.session.add(
                    RolePermissionORM(role_id=role.id, permission_id=perm_id)
                )

        await self.user_repo.session.commit()
        return await self._refresh_role(role.id)

    async def delete_tenant_role(self, tenant_id: uuid.UUID, role_id: uuid.UUID) -> None:
        role = await self.get_role_in_tenant(tenant_id, role_id=role_id)
        if not role:
            raise ValueError("Role not found")

        if role.is_protected_tenant_role:
            raise ValueError("Cannot delete protected system roles")

        in_use = await self.user_repo.session.execute(
            select(UserRoleORM).where(UserRoleORM.role_id == role_id).limit(1)
        )
        if in_use.scalar_one_or_none():
            raise ValueError("Cannot delete a role that is assigned to users")

        await self.user_repo.session.delete(role)
        await self.user_repo.session.commit()

    async def delete_role(self, role_id: uuid.UUID) -> None:
        result = await self.user_repo.session.execute(select(RoleORM).where(RoleORM.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise ValueError("Role not found")

        if role.tenant_id is not None:
            raise ValueError("Use tenant role endpoints to delete organization roles")

        if role.name in PLATFORM_SYSTEM_ROLE_NAMES or role.name in PROTECTED_TENANT_TEMPLATE_NAMES:
            raise ValueError("Cannot delete system roles")

        await self.user_repo.session.delete(role)
        await self.user_repo.session.commit()

    async def assign_role(
        self,
        actor: UserORM,
        target_user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        *,
        role_name: str | None = None,
        role_id: uuid.UUID | None = None,
        as_platform_admin: bool = False,
    ) -> None:
        tenant = await self.user_repo.session.get(TenantORM, tenant_id)
        if not tenant:
            raise ValueError("Tenant not found")

        if tenant.type == TenantType.PLATFORM:
            if role_id:
                result = await self.user_repo.session.execute(
                    select(RoleORM).where(
                        RoleORM.id == role_id,
                        RoleORM.scope == RoleScope.PLATFORM,
                        RoleORM.tenant_id.is_(None),
                    )
                )
                target_role = result.scalar_one_or_none()
            else:
                result = await self.user_repo.session.execute(
                    select(RoleORM).where(
                        RoleORM.name == role_name,
                        RoleORM.scope == RoleScope.PLATFORM,
                        RoleORM.tenant_id.is_(None),
                    )
                )
                target_role = result.scalar_one_or_none()
        else:
            target_role = await self.get_role_in_tenant(
                tenant_id, role_id=role_id, role_name=role_name
            )

        if not target_role:
            raise ValueError("Role not found in this organization")

        if target_role.is_template:
            raise ValueError("Template roles cannot be assigned directly")

        if target_role.name == "SUPER_ADMIN":
            raise ValueError("SUPER_ADMIN role cannot be assigned manually")

        if target_role.scope == RoleScope.PLATFORM and tenant.type != TenantType.PLATFORM:
            raise ValueError("Platform roles can only be assigned in platform tenant")

        if target_role.scope == RoleScope.TENANT and tenant.type == TenantType.PLATFORM:
            raise ValueError("Tenant roles cannot be assigned in platform tenant")

        perm_required = (
            "tenant.roles.assign"
            if target_role.scope == RoleScope.TENANT
            else "platform.roles.assign"
        )
        if as_platform_admin:
            if not await PermissionService.has_permission(
                self.user_repo.session, actor, "platform.users.manage", None
            ):
                raise ValueError("Insufficient permissions: Missing 'platform.users.manage'")
        elif not await PermissionService.has_permission(
            self.user_repo.session, actor, perm_required, tenant_id
        ):
            raise ValueError(f"Insufficient permissions: Missing '{perm_required}'")

        max_actor_level = -1
        for ur in actor.roles:
            if ur.tenant_id == tenant_id or ur.role.scope == RoleScope.PLATFORM:
                if ur.role.level > max_actor_level:
                    max_actor_level = ur.role.level

        if max_actor_level == -1:
            raise ValueError("Insufficient permissions: You have no active roles for this context")

        if target_role.level >= max_actor_level:
            raise ValueError(
                f"Insufficient level: You cannot assign a role with level {target_role.level} "
                f"(your max level {max_actor_level} must be strictly higher)"
            )

        check_query = select(UserRoleORM).where(
            UserRoleORM.user_id == target_user_id,
            UserRoleORM.role_id == target_role.id,
            UserRoleORM.tenant_id == tenant_id,
        )
        existing = await self.user_repo.session.execute(check_query)
        if existing.scalar_one_or_none():
            return

        self.user_repo.session.add(
            UserRoleORM(
                user_id=target_user_id,
                role_id=target_role.id,
                tenant_id=tenant_id,
            )
        )
        await self.user_repo.session.commit()

        if self.audit_service:
            await self.audit_service.log(
                actor_id=actor.id,
                target_user_id=target_user_id,
                tenant_id=str(tenant_id),
                action="ROLE_ASSIGNED",
                resource="UserRole",
                metadata={
                    "role_name": target_role.name,
                    "role_id": str(target_role.id),
                    "role_level": target_role.level,
                },
            )

    async def remove_role(
        self,
        actor: UserORM,
        target_user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        *,
        role_name: str | None = None,
        role_id: uuid.UUID | None = None,
        as_platform_admin: bool = False,
    ) -> bool:
        tenant = await self.user_repo.session.get(TenantORM, tenant_id)
        if not tenant:
            raise ValueError("Tenant not found")

        if tenant.type == TenantType.PLATFORM:
            if role_id:
                result = await self.user_repo.session.execute(
                    select(RoleORM).where(
                        RoleORM.id == role_id, RoleORM.scope == RoleScope.PLATFORM
                    )
                )
                target_role = result.scalar_one_or_none()
            else:
                result = await self.user_repo.session.execute(
                    select(RoleORM).where(
                        RoleORM.name == role_name, RoleORM.scope == RoleScope.PLATFORM
                    )
                )
                target_role = result.scalar_one_or_none()
        else:
            target_role = await self.get_role_in_tenant(
                tenant_id, role_id=role_id, role_name=role_name
            )

        if not target_role:
            raise ValueError("Role not found in this organization")

        if target_role.name == "SUPER_ADMIN":
            raise ValueError("SUPER_ADMIN role cannot be removed manually")

        perm_required = (
            "tenant.roles.assign"
            if target_role.scope == RoleScope.TENANT
            else "platform.roles.assign"
        )
        if as_platform_admin:
            if not await PermissionService.has_permission(
                self.user_repo.session, actor, "platform.users.manage", None
            ):
                raise ValueError("Insufficient permissions: Missing 'platform.users.manage'")
        elif not await PermissionService.has_permission(
            self.user_repo.session, actor, perm_required, tenant_id
        ):
            raise ValueError(f"Insufficient permissions: Missing '{perm_required}'")

        max_actor_level = -1
        for ur in actor.roles:
            if ur.tenant_id == tenant_id or ur.role.scope == RoleScope.PLATFORM:
                if ur.role.level > max_actor_level:
                    max_actor_level = ur.role.level

        if max_actor_level == -1:
            raise ValueError("Insufficient permissions: You have no active roles for this context")

        if target_role.level >= max_actor_level:
            raise ValueError(
                f"Insufficient level: You cannot remove a role with level {target_role.level} "
                f"(your max level {max_actor_level} must be strictly higher)"
            )

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
                    metadata={"role_name": target_role.name, "role_id": str(target_role.id)},
                )
            return True
        return False

    async def get_user_roles_in_tenant(
        self, user_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[UserRoleORM]:
        query = (
            select(UserRoleORM)
            .where(UserRoleORM.user_id == user_id, UserRoleORM.tenant_id == tenant_id)
            .options(joinedload(UserRoleORM.role).joinedload(RoleORM.permissions))
        )
        result = await self.user_repo.session.execute(query)
        return list(result.unique().scalars().all())

    async def list_tenant_assignable_permissions(self) -> list[PermissionORM]:
        result = await self.user_repo.session.execute(
            select(PermissionORM).where(
                or_(
                    PermissionORM.name.startswith("tenant."),
                    PermissionORM.name.startswith("auth."),
                )
            )
        )
        return list(result.scalars().all())
