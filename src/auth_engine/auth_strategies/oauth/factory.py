# auth_strategies/oauth/factory.py
"""
OAuthProviderFactory — builds the correct strategy instance based on provider name.

Tenant-aware: resolves per-tenant OAuth credentials from the DB.
Falls back to the canonical platform tenant when the requesting tenant has no row.
"""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.constants import AUTHENGINE_OIDC, GITHUB, GOOGLE, MICROSOFT
from auth_engine.auth_strategies.oauth import (
    BaseOAuthStrategy,
    GitHubOAuthStrategy,
    GoogleOAuthStrategy,
    MicrosoftOAuthStrategy,
)
from auth_engine.auth_strategies.oauth.authengine import (
    AuthEngineOAuthStrategy,
    resolve_authengine_endpoints,
)
from auth_engine.core.exceptions import AuthenticationError
from auth_engine.core.security import SecurityUtils
from auth_engine.models.tenant_social_provider import TenantSocialProviderORM
from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id

logger = logging.getLogger(__name__)


async def _load_tenant_provider(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    provider: str,
) -> TenantSocialProviderORM | None:
    query = select(TenantSocialProviderORM).where(
        TenantSocialProviderORM.tenant_id == tenant_id,
        TenantSocialProviderORM.provider == provider,
        TenantSocialProviderORM.is_active.is_(True),
    )
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_oauth_strategy(
    provider: str,
    db: AsyncSession,
    tenant_id: uuid.UUID | str | None = None,
) -> BaseOAuthStrategy:
    """
    Return a configured OAuth strategy for the given provider name.

    Loads tenant-specific credentials from DB, then falls back to the platform tenant.
    """
    provider = provider.lower()

    resolved_tenant_id: uuid.UUID | None = None
    if tenant_id is not None:
        if isinstance(tenant_id, str):
            try:
                resolved_tenant_id = uuid.UUID(tenant_id)
            except ValueError:
                resolved_tenant_id = None
        else:
            resolved_tenant_id = tenant_id

    tenant_ids_to_try: list[uuid.UUID] = []
    if resolved_tenant_id is not None:
        tenant_ids_to_try.append(resolved_tenant_id)

    platform_id = await get_canonical_platform_tenant_id(db)
    if platform_id is not None and platform_id not in tenant_ids_to_try:
        tenant_ids_to_try.append(platform_id)

    for tid in tenant_ids_to_try:
        tenant_provider = await _load_tenant_provider(db, tid, provider)
        if tenant_provider:
            client_id = SecurityUtils.decrypt_data(tenant_provider.client_id)
            client_secret = SecurityUtils.decrypt_data(tenant_provider.client_secret)
            return await _build_strategy(
                provider,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=tenant_provider.redirect_uri,
                authengine_base_url=tenant_provider.oidc_discovery_url,
            )

    raise AuthenticationError(
        f"OAuth provider '{provider}' is not configured for this organization. "
        "Add it under tenant social providers."
    )


async def _build_authengine_strategy(
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    base_url: str,
) -> AuthEngineOAuthStrategy:
    endpoints = await resolve_authengine_endpoints(base_url)
    return AuthEngineOAuthStrategy(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        authorization_url=endpoints["authorization_endpoint"],
        token_url=endpoints["token_endpoint"],
        userinfo_url=endpoints["userinfo_endpoint"],
    )


async def _build_strategy(
    provider: str,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str | None,
    authengine_base_url: str | None = None,
) -> BaseOAuthStrategy:
    """Instantiate a strategy with the given credentials."""

    if provider == GOOGLE:
        if not redirect_uri:
            raise AuthenticationError("Google OAuth redirect URI is not configured.")
        return GoogleOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    if provider == GITHUB:
        if not redirect_uri:
            raise AuthenticationError("GitHub OAuth redirect URI is not configured.")
        return GitHubOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    if provider == MICROSOFT:
        if not redirect_uri:
            raise AuthenticationError("Microsoft OAuth redirect URI is not configured.")
        return MicrosoftOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    if provider == AUTHENGINE_OIDC:
        base_url = authengine_base_url or ""
        if not base_url:
            raise AuthenticationError(
                "AuthEngine provider requires oidc_discovery_url in "
                "the tenant social provider config."
            )
        if not redirect_uri:
            raise AuthenticationError("AuthEngine OAuth redirect URI is not configured.")
        return await _build_authengine_strategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            base_url=base_url,
        )

    raise AuthenticationError(
        f"Unknown OAuth provider: '{provider}'. "
        f"Supported: google, github, microsoft, authengine"
    )


async def get_platform_authengine_client_id(db: AsyncSession) -> str | None:
    """Return the decrypted AuthEngine OAuth client id for the platform tenant."""
    platform_id = await get_canonical_platform_tenant_id(db)
    if not platform_id:
        return None

    row = await _load_tenant_provider(db, platform_id, AUTHENGINE_OIDC)
    if not row:
        return None

    return SecurityUtils.decrypt_data(row.client_id)
