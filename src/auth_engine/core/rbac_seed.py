import logging
import uuid

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.permission import PermissionORM
from auth_engine.models.role import RoleORM, RoleScope
from auth_engine.models.role_permission import RolePermissionORM

logger = logging.getLogger(__name__)

DEFAULT_ROLES = [
    ("SUPER_ADMIN", "Full platform control", RoleScope.PLATFORM, 100),
    ("PLATFORM_ADMIN", "Manage organizations", RoleScope.PLATFORM, 80),
    ("TENANT_OWNER", "Owner of organization", RoleScope.TENANT, 60),
    ("TENANT_ADMIN", "Admin inside tenant", RoleScope.TENANT, 50),
    ("TENANT_MANAGER", "Manager inside tenant", RoleScope.TENANT, 30),
    ("TENANT_USER", "Standard tenant user", RoleScope.TENANT, 10),
]

DEFAULT_PERMISSIONS = [
    ("platform.users.view", "View all users globally"),
    ("platform.users.manage", "Manage all users globally"),
    ("platform.roles.assign", "Assign platform-level roles"),
    ("platform.tenants.view", "View all tenants globally"),
    ("platform.tenants.manage", "Manage all tenants globally"),
    ("platform.audit.view", "View all audit logs globally"),
    ("tenant.view", "View tenant details"),
    ("tenant.update", "Update tenant details"),
    ("tenant.delete", "Delete tenant"),
    ("tenant.users.view", "View users in tenant"),
    ("tenant.users.manage", "Manage users in tenant"),
    ("tenant.roles.view", "View roles in tenant"),
    ("tenant.roles.assign", "Assign roles in tenant"),
    ("auth.tokens.request", "Request authentication and verification tokens"),
    ("auth.password.reset", "Initiate and perform password reset"),
    ("auth.email.verify", "Perform email verification"),
    ("auth.phone.verify", "Perform phone verification"),
    ("auth.tokens.refresh", "Refresh authentication tokens"),
]

ROLE_PERMISSIONS = {
    "SUPER_ADMIN": [p[0] for p in DEFAULT_PERMISSIONS],
    "PLATFORM_ADMIN": [
        "platform.users.view",
        "platform.tenants.view",
        "platform.tenants.manage",
        "platform.roles.assign",
        "platform.audit.view",
        "tenant.view",
        "tenant.update",
        "tenant.delete",
        "tenant.users.view",
        "auth.tokens.request",
        "auth.password.reset",
        "auth.email.verify",
        "auth.phone.verify",
        "auth.tokens.refresh",
    ],
    "TENANT_OWNER": [
        "tenant.view",
        "tenant.update",
        "tenant.delete",
        "tenant.users.view",
        "tenant.users.manage",
        "tenant.roles.view",
        "tenant.roles.assign",
        "auth.tokens.request",
        "auth.password.reset",
        "auth.email.verify",
        "auth.phone.verify",
        "auth.tokens.refresh",
    ],
    "TENANT_ADMIN": [
        "tenant.view",
        "tenant.update",
        "tenant.users.view",
        "tenant.users.manage",
        "tenant.roles.view",
        "tenant.roles.assign",
        "auth.tokens.request",
        "auth.password.reset",
        "auth.email.verify",
        "auth.phone.verify",
        "auth.tokens.refresh",
    ],
    "TENANT_MANAGER": [
        "tenant.view",
        "tenant.users.view",
        "tenant.roles.view",
        "tenant.roles.assign",
        "auth.tokens.request",
        "auth.password.reset",
        "auth.email.verify",
        "auth.phone.verify",
        "auth.tokens.refresh",
    ],
    "TENANT_USER": [
        "tenant.view",
        "auth.tokens.request",
        "auth.password.reset",
        "auth.email.verify",
        "auth.phone.verify",
        "auth.tokens.refresh",
    ],
}


async def seed_roles(db: AsyncSession) -> None:
    # ── 1. Bulk upsert roles (1 query) ──────────────────────────────────────
    role_rows = [
        {"name": name, "description": desc, "scope": scope, "level": level}
        for name, desc, scope, level in DEFAULT_ROLES
    ]
    await db.execute(
        insert(RoleORM)
        .values(role_rows)
        .on_conflict_do_update(
            index_elements=["name"],
            set_={"description": insert(RoleORM).excluded.description,
                  "scope": insert(RoleORM).excluded.scope,
                  "level": insert(RoleORM).excluded.level},
        )
    )

    # ── 2. Bulk upsert permissions (1 query) ────────────────────────────────
    perm_rows = [
        {"name": name, "description": desc}
        for name, desc in DEFAULT_PERMISSIONS
    ]
    await db.execute(
        insert(PermissionORM)
        .values(perm_rows)
        .on_conflict_do_update(
            index_elements=["name"],
            set_={"description": insert(PermissionORM).excluded.description},
        )
    )

    await db.flush()

    # ── 3. Fetch all roles + permissions in 2 queries ───────────────────────
    roles = {r.name: r for r in (await db.execute(select(RoleORM))).scalars().all()}
    perms = {p.name: p for p in (await db.execute(select(PermissionORM))).scalars().all()}

    # ── 4. Bulk upsert role-permission associations (1 query) ───────────────
    assoc_rows = [
        {"role_id": roles[role_name].id, "permission_id": perms[perm_name].id}
        for role_name, perm_names in ROLE_PERMISSIONS.items()
        for perm_name in perm_names
        if role_name in roles and perm_name in perms
    ]

    if assoc_rows:
        await db.execute(
            insert(RolePermissionORM)
            .values(assoc_rows)
            .on_conflict_do_nothing()
        )

    await db.commit()
    logger.info("Roles and permissions seeded successfully")
