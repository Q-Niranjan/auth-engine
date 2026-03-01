import logging

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.config import settings
from auth_engine.core.security import security as security_utils
from auth_engine.models import RoleORM, TenantORM, UserORM, UserRoleORM
from auth_engine.models.tenant import TenantType
from auth_engine.schemas.user import UserStatus

logger = logging.getLogger(__name__)


async def seed_super_admin(db: AsyncSession) -> None:
    """
    Idempotent super admin bootstrap.
    Single query early-exit — near zero cost on subsequent startups.
    """

    # ── Single query: fetch role + user + tenant + assignment together ───────
    # If all 4 exist and are linked, we're done in 1 round trip
    full_check = await db.execute(
        select(
            RoleORM,
            UserORM,
            TenantORM,
            UserRoleORM,
        )
        .join(UserRoleORM, RoleORM.id == UserRoleORM.role_id)
        .join(UserORM, UserORM.id == UserRoleORM.user_id)
        .join(TenantORM, TenantORM.id == UserRoleORM.tenant_id)
        .where(RoleORM.name == "SUPER_ADMIN")
        .where(TenantORM.type == TenantType.PLATFORM)
        .limit(1)
    )
    row = full_check.first()

    if row:
        logger.debug("Super admin fully seeded — skipping")
        return

    logger.info("Bootstrapping super admin...")

    # ── Fetch only what's missing ────────────────────────────────────────────
    results = await db.execute(
        select(RoleORM, UserORM, TenantORM)
        .outerjoin(UserORM, UserORM.email == settings.SUPERADMIN_EMAIL)
        .outerjoin(TenantORM, TenantORM.type == TenantType.PLATFORM)
        .where(RoleORM.name == "SUPER_ADMIN")
        .limit(1)
    )
    row = results.first()

    if not row or not row.RoleORM:
        logger.warning("SUPER_ADMIN role not found — ensure seed_roles ran first")
        return

    super_admin_role: RoleORM = row.RoleORM
    user: UserORM | None = row.UserORM
    platform: TenantORM | None = row.TenantORM

    # ── Create user if missing ───────────────────────────────────────────────
    if not user:
        user = UserORM(
            email=settings.SUPERADMIN_EMAIL,
            username="superadmin",
            password_hash=security_utils.hash_password(settings.SUPERADMIN_PASSWORD),
            first_name="Super",
            last_name="Admin",
            status=UserStatus.ACTIVE,
            is_email_verified=True,
        )
        db.add(user)
        await db.flush()
        logger.info(f"Created super admin user: {settings.SUPERADMIN_EMAIL}")

    # ── Create platform tenant if missing ────────────────────────────────────
    if not platform:
        platform = TenantORM(
            name="Platform",
            type=TenantType.PLATFORM,
            description="System platform tenant",
            owner_id=user.id,
            created_by=user.id,
        )
        db.add(platform)
        await db.flush()
        logger.info("Created platform tenant")

    # ── Assign role — single upsert, ignore if exists ────────────────────────
    await db.execute(
        insert(UserRoleORM)
        .values(
            user_id=user.id,
            role_id=super_admin_role.id,
            tenant_id=platform.id,
        )
        .on_conflict_do_nothing()
    )

    await db.commit()
    logger.info("Super admin bootstrap complete")
