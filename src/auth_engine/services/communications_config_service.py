"""Shared helpers for tenant email/SMS configuration."""

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models.email_config import TenantEmailConfigORM
from auth_engine.models.sms_config import TenantSMSConfigORM

IMPLEMENTED_EMAIL_PROVIDERS = ("sendgrid", "ses")
IMPLEMENTED_SMS_PROVIDERS = ("twilio", "android_gateway")


async def deactivate_other_email_configs(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    keep_id: uuid.UUID,
) -> None:
    await db.execute(
        update(TenantEmailConfigORM)
        .where(
            TenantEmailConfigORM.tenant_id == tenant_id,
            TenantEmailConfigORM.id != keep_id,
            TenantEmailConfigORM.is_active.is_(True),
        )
        .values(is_active=False)
    )


async def deactivate_other_sms_configs(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    keep_id: uuid.UUID,
) -> None:
    await db.execute(
        update(TenantSMSConfigORM)
        .where(
            TenantSMSConfigORM.tenant_id == tenant_id,
            TenantSMSConfigORM.id != keep_id,
            TenantSMSConfigORM.is_active.is_(True),
        )
        .values(is_active=False)
    )


async def tenant_has_email_configs(db: AsyncSession, tenant_id: uuid.UUID) -> bool:
    result = await db.execute(
        select(TenantEmailConfigORM.id).where(TenantEmailConfigORM.tenant_id == tenant_id).limit(1)
    )
    return result.scalar_one_or_none() is not None


async def tenant_has_sms_configs(db: AsyncSession, tenant_id: uuid.UUID) -> bool:
    result = await db.execute(
        select(TenantSMSConfigORM.id).where(TenantSMSConfigORM.tenant_id == tenant_id).limit(1)
    )
    return result.scalar_one_or_none() is not None
