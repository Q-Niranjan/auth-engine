"""Resolve email/SMS from tenant rows, inheriting from the platform tenant."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id

logger = logging.getLogger(__name__)


async def resolve_config_tenant_id(
    session: AsyncSession,
    tenant_id: uuid.UUID | str | None,
) -> uuid.UUID | None:
    """Return the tenant whose config row should be used (self or platform fallback)."""
    if tenant_id is None or tenant_id == "default":
        return await get_canonical_platform_tenant_id(session)

    resolved: uuid.UUID | None
    if isinstance(tenant_id, str):
        try:
            resolved = uuid.UUID(tenant_id)
        except ValueError:
            logger.warning("Invalid tenant_id format: %s", tenant_id)
            return await get_canonical_platform_tenant_id(session)
    else:
        resolved = tenant_id

    return resolved
