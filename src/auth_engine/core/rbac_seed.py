import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.permission import PermissionORM
from auth_engine.models.role import RoleORM
from auth_engine.models.role_permission import RolePermissionORM

logger = logging.getLogger(__name__)

DEFAULT_ROLES = [
    ("SUPER_ADMIN", "Full platform control", "platform"),
    ("PLATFORM_ADMIN", "Manage organizations", "platform"),
    ("TENANT_OWNER", "Owner of organization", "tenant"),
    ("TENANT_ADMIN", "Admin inside tenant", "tenant"),
    ("TENANT_MANAGER", "Manager inside tenant", "tenant"),
    ("TENANT_USER", "Standard tenant user", "tenant"),
]

# (Permission Name, Description)
DEFAULT_PERMISSIONS = [
    ("platform.users.view", "View all users globally"),
    ("platform.users.manage", "Manage all users globally"),
    ("platform.tenants.view", "View all tenants globally"),
    ("platform.tenants.manage", "Manage all tenants globally"),
    ("tenant.view", "View tenant details"),
    ("tenant.update", "Update tenant details"),
    ("tenant.delete", "Delete tenant"),
    ("tenant.users.view", "View users in tenant"),
    ("tenant.users.manage", "Manage users in tenant"),
    ("tenant.roles.view", "View roles in tenant"),
    ("tenant.roles.assign", "Assign roles in tenant"),
]

ROLE_PERMISSIONS = {
    "SUPER_ADMIN": [p[0] for p in DEFAULT_PERMISSIONS],
    "PLATFORM_ADMIN": [
        "platform.users.view",
        "platform.tenants.view",
        "platform.tenants.manage",
        "tenant.view",
        "tenant.users.view",
    ],
    "TENANT_OWNER": [
        "tenant.view",
        "tenant.update",
        "tenant.delete",
        "tenant.users.view",
        "tenant.users.manage",
        "tenant.roles.view",
        "tenant.roles.assign",
    ],
    "TENANT_ADMIN": [
        "tenant.view",
        "tenant.update",
        "tenant.users.view",
        "tenant.users.manage",
        "tenant.roles.view",
        "tenant.roles.assign",
    ],
    "TENANT_MANAGER": [
        "tenant.view",
        "tenant.users.view",
        "tenant.roles.view",
        "tenant.roles.assign",
    ],
    "TENANT_USER": [
        "tenant.view",
    ],
}


async def seed_roles(db: AsyncSession) -> None:
    # 1. Seed Roles
    role_objs: dict[str, RoleORM] = {}
    for name, description, scope in DEFAULT_ROLES:
        role_query = select(RoleORM).where(RoleORM.name == name)
        role_result = await db.execute(role_query)
        role = role_result.scalar_one_or_none()

        if not role:
            logger.info(f"Seeding role: {name}")
            role = RoleORM(name=name, description=description, scope=scope)
            db.add(role)
        else:
            role.description = description
            role.scope = scope
        role_objs[name] = role

    # 2. Seed Permissions
    permission_objs: dict[str, PermissionORM] = {}
    for name, description in DEFAULT_PERMISSIONS:
        perm_query = select(PermissionORM).where(PermissionORM.name == name)
        perm_result = await db.execute(perm_query)
        perm = perm_result.scalar_one_or_none()

        if not perm:
            logger.info(f"Seeding permission: {name}")
            perm = PermissionORM(name=name, description=description)
            db.add(perm)
        else:
            perm.description = description
        permission_objs[name] = perm

    await db.flush()  # Ensure IDs are populated

    # 3. Associate Permissions with Roles
    for role_name, perms in ROLE_PERMISSIONS.items():
        role = role_objs[role_name]
        for perm_name in perms:
            perm = permission_objs[perm_name]

            # Check if association already exists
            assoc_query = select(RolePermissionORM).where(
                RolePermissionORM.role_id == role.id, RolePermissionORM.permission_id == perm.id
            )
            assoc_result = await db.execute(assoc_query)
            if not assoc_result.scalar_one_or_none():
                db.add(RolePermissionORM(role_id=role.id, permission_id=perm.id))

    await db.commit()
