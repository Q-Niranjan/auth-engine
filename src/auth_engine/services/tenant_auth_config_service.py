"""Shared tenant auth-config helpers."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.models import TenantAuthConfigORM
from auth_engine.schemas.tenant_auth_config import (
    DEFAULT_ALLOWED_METHODS,
    DEFAULT_PASSWORD_POLICY,
    LEGACY_SOCIAL_METHODS,
    VALID_AUTH_METHODS,
    resolve_password_policy,
)

CANONICAL_AUTH_METHODS = (
    "email_password",
    "magic_link",
    "social_provider",
    "passkey",
)


def normalize_allowed_methods(methods: list[str] | None) -> list[str]:
    """Map legacy provider-specific entries to canonical login methods."""
    if not methods:
        return []

    normalized: list[str] = []
    seen: set[str] = set()

    for method in methods:
        canonical = method
        if method in LEGACY_SOCIAL_METHODS or method == "oauth":
            canonical = "social_provider"
        elif method == "webauthn":
            canonical = "passkey"

        if canonical in VALID_AUTH_METHODS and canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)

    return normalized


def is_method_allowed(methods: list[str] | None, method: str) -> bool:
    return method in normalize_allowed_methods(methods)


async def get_effective_password_policy(
    db: AsyncSession,
    tenant_id: uuid.UUID | None = None,
) -> dict:
    """Resolve password rules for a tenant, falling back to the platform tenant."""
    from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id

    async def _policy_for(tid: uuid.UUID) -> dict | None:
        config = await get_or_create_auth_config(db, tid)
        if not config.password_policy:
            return None
        return resolve_password_policy(config.password_policy)

    if tenant_id is not None:
        tenant_policy = await _policy_for(tenant_id)
        if tenant_policy is not None:
            return tenant_policy

    platform_id = await get_canonical_platform_tenant_id(db)
    if platform_id is not None and platform_id != tenant_id:
        platform_policy = await _policy_for(platform_id)
        if platform_policy is not None:
            return platform_policy

    return DEFAULT_PASSWORD_POLICY.copy()


async def get_or_create_auth_config(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> TenantAuthConfigORM:
    from auth_engine.models import TenantORM

    tenant_exists = await db.scalar(select(TenantORM.id).where(TenantORM.id == tenant_id))
    if not tenant_exists:
        raise ValueError(f"Tenant {tenant_id} not found")

    result = await db.execute(
        select(TenantAuthConfigORM).where(TenantAuthConfigORM.tenant_id == tenant_id)
    )
    config = result.scalar_one_or_none()
    if config:
        return config

    config = TenantAuthConfigORM(
        tenant_id=tenant_id,
        allowed_methods=DEFAULT_ALLOWED_METHODS,
        mfa_required=False,
        password_policy=DEFAULT_PASSWORD_POLICY,
        session_ttl_seconds=3600,
        allowed_domains=[],
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return config
