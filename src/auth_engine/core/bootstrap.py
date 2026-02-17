from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.config import settings
from auth_engine.core.security import security as security_utils
from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.models.tenant import TenantType


async def seed_super_admin(db: AsyncSession) -> None:
    """
    Seeds a SUPER_ADMIN user if none exists.
    """
    # Check if any SUPER_ADMIN already exists
    query = select(UserORM).join(UserRoleORM).join(RoleORM).where(RoleORM.name == "SUPER_ADMIN")
    result = await db.execute(query)
    if result.scalars().first():
        return

    # No super admin found, let's create one
    # First, find the SUPER_ADMIN role ID
    role_query = select(RoleORM).where(RoleORM.name == "SUPER_ADMIN")
    role_result = await db.execute(role_query)
    super_admin_role = role_result.scalar_one_or_none()

    if not super_admin_role:
        # This shouldn't happen if seed_roles was called first
        # But for safety, we return if role definitions are missing
        return

    # Check if user with this email already exists
    user_query = select(UserORM).where(UserORM.email == settings.SUPERADMIN_EMAIL)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        # Create new user
        user = UserORM(
            email=settings.SUPERADMIN_EMAIL,
            username="admin",
            password_hash=security_utils.hash_password(settings.SUPERADMIN_PASSWORD),
            first_name="Super",
            last_name="Admin",
            status="active",
            is_email_verified=True,
        )
        db.add(user)
        await db.flush()

    # 1. Ensure Platform Tenant Exists
    platform_query = select(TenantORM).where(TenantORM.type == TenantType.PLATFORM)
    platform_result = await db.execute(platform_query)
    platform = platform_result.scalar_one_or_none()

    if not platform:
        platform = TenantORM(
            name="Platform", type=TenantType.PLATFORM, description="System platform tenant"
        )
        db.add(platform)
        await db.flush()

    # 2. Check if user already has this role in this tenant
    assignment_query = select(UserRoleORM).where(
        UserRoleORM.user_id == user.id,
        UserRoleORM.role_id == super_admin_role.id,
        UserRoleORM.tenant_id == platform.id,
    )
    assignment_result = await db.execute(assignment_query)
    if not assignment_result.scalar_one_or_none():
        # Assign role to platform tenant
        db.add(UserRoleORM(user_id=user.id, role_id=super_admin_role.id, tenant_id=platform.id))
        await db.commit()
    else:
        await db.rollback()  # Nothing to do, but good practice to close transaction if opened
