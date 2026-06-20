import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.constants import SUPPORTED_PROVIDERS
from auth_engine.models.tenant import TenantORM, TenantType
from auth_engine.models.tenant_social_provider import TenantSocialProviderORM


async def get_canonical_platform_tenant_id(db: AsyncSession) -> uuid.UUID | None:
    result = await db.execute(
        select(TenantORM.id)
        .where(TenantORM.type == TenantType.PLATFORM)
        .order_by(TenantORM.created_at.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def list_active_oauth_providers(
    db: AsyncSession,
    tenant_id: uuid.UUID | None = None,
) -> list[tuple[str, uuid.UUID]]:
    """Return active OAuth providers for a single tenant only."""
    resolved_tenant_id = tenant_id
    if resolved_tenant_id is None:
        resolved_tenant_id = await get_canonical_platform_tenant_id(db)

    if not resolved_tenant_id:
        return []

    result = await db.execute(
        select(
            TenantSocialProviderORM.provider,
            TenantSocialProviderORM.tenant_id,
        ).where(
            TenantSocialProviderORM.tenant_id == resolved_tenant_id,
            TenantSocialProviderORM.is_active.is_(True),
        )
    )

    providers: list[tuple[str, uuid.UUID]] = []
    for provider, tid in result.all():
        if provider in SUPPORTED_PROVIDERS:
            providers.append((provider, tid))
    return providers
