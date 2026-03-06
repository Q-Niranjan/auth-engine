# auth_strategies/oauth/factory.py
"""
OAuthProviderFactory — builds the correct strategy instance based on provider name.

Tenant-aware: resolves per-tenant OAuth credentials from the DB when a
tenant_id is provided. Falls back to platform credentials from settings.

Supported providers: google, github, microsoft, authengine
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.auth_strategies.constants import AUTHENGINE_OIDC, GITHUB, GOOGLE, MICROSOFT
from auth_engine.auth_strategies.oauth import (
    AuthEngineOAuthStrategy,
    BaseOAuthStrategy,
    GitHubOAuthStrategy,
    GoogleOAuthStrategy,
    MicrosoftOAuthStrategy,
)
from auth_engine.core.config import settings
from auth_engine.core.exceptions import AuthenticationError
from auth_engine.core.security import SecurityUtils
from auth_engine.models.tenant_social_provider import TenantSocialProviderORM

import logging
logger = logging.getLogger(__name__)

async def get_oauth_strategy(
    provider: str,
    db: AsyncSession,
    tenant_id: uuid.UUID | str | None = None,
) -> BaseOAuthStrategy:
    """
    Return a configured OAuth strategy for the given provider name.

    If tenant_id is provided, loads tenant-specific credentials from DB first.
    Falls back to platform-level credentials from settings.

    Args:
        provider:  One of "google", "github", "microsoft", "authengine"
        db:        Async database session
        tenant_id: Optional tenant context

    Returns:
        Configured strategy instance

    Raises:
        AuthenticationError: If provider is unknown or not configured
    """
    provider = provider.lower()

    # Resolve tenant_id to UUID
    resolved_tenant_id: uuid.UUID | None = None
    if tenant_id is not None:
        if isinstance(tenant_id, str):
            try:
                resolved_tenant_id = uuid.UUID(tenant_id)
            except ValueError:
                resolved_tenant_id = None
        else:
            resolved_tenant_id = tenant_id

    # Try tenant-specific credentials first
    if resolved_tenant_id is not None:
        query = select(TenantSocialProviderORM).where(
            TenantSocialProviderORM.tenant_id == resolved_tenant_id,
            TenantSocialProviderORM.provider == provider,
            TenantSocialProviderORM.is_active.is_(True),
        )
        result = await db.execute(query)
        tenant_provider = result.scalar_one_or_none()

        if tenant_provider:
            client_id = SecurityUtils.decrypt_data(tenant_provider.client_id)
            client_secret = SecurityUtils.decrypt_data(tenant_provider.client_secret)
            redirect_uri = tenant_provider.redirect_uri

            return _build_strategy(
                provider,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                # For AuthEngine provider, oidc_discovery_url stores the base URL
                authengine_base_url=tenant_provider.oidc_discovery_url,
            )

    # Fall back to platform-level settings
    return _build_platform_strategy(provider)


def _build_strategy(
    provider: str,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str | None,
    authengine_base_url: str | None = None,
) -> BaseOAuthStrategy:
    """Instantiate a strategy with the given credentials."""

    if provider == GOOGLE:
        return GoogleOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri or settings.GOOGLE_REDIRECT_URI,
        )

    if provider == GITHUB:
        return GitHubOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri or settings.GITHUB_REDIRECT_URI,
        )

    if provider == MICROSOFT:
        return MicrosoftOAuthStrategy(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri or settings.MICROSOFT_REDIRECT_URI,
        )

    if provider == AUTHENGINE_OIDC:
        base_url = authengine_base_url or settings.AUTHENGINE_BASE_URL
        if not base_url:
            raise AuthenticationError(
                "AuthEngine provider requires AUTHENGINE_BASE_URL. "
                "Set it in .env or in the tenant social provider config."
            )
        return AuthEngineOAuthStrategy(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri or settings.AUTHENGINE_REDIRECT_URI,
        )

    raise AuthenticationError(
        f"Unknown OAuth provider: '{provider}'. "
        f"Supported: google, github, microsoft, authengine"
    )




def _build_platform_strategy(provider: str) -> BaseOAuthStrategy:
    """Build a strategy using platform-level credentials from settings."""
    logger.debug(f"Building platform strategy for: {provider}")

    if provider == GOOGLE:
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            logger.warning("Google OAuth is not configured")
            raise AuthenticationError("Google OAuth is not configured.")
        return GoogleOAuthStrategy(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
        )

    if provider == GITHUB:
        if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
            logger.warning("GitHub OAuth is not configured")
            raise AuthenticationError("GitHub OAuth is not configured.")
        return GitHubOAuthStrategy(
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET,
            redirect_uri=settings.GITHUB_REDIRECT_URI,
        )

    if provider == MICROSOFT:
        if not settings.MICROSOFT_CLIENT_ID or not settings.MICROSOFT_CLIENT_SECRET:
            logger.warning("Microsoft OAuth is not configured")
            raise AuthenticationError("Microsoft OAuth is not configured.")
        return MicrosoftOAuthStrategy(
            client_id=settings.MICROSOFT_CLIENT_ID,
            client_secret=settings.MICROSOFT_CLIENT_SECRET,
            redirect_uri=settings.MICROSOFT_REDIRECT_URI,
        )

    if provider == AUTHENGINE_OIDC:
        logger.debug(f"Configuring AuthEngine: ID={'set' if settings.AUTHENGINE_CLIENT_ID else 'empty'}, Secret={'set' if settings.AUTHENGINE_CLIENT_SECRET else 'empty'}, Base={settings.AUTHENGINE_BASE_URL}")
        if not settings.AUTHENGINE_CLIENT_ID or not settings.AUTHENGINE_CLIENT_SECRET:
            raise AuthenticationError(
                "AuthEngine OAuth is not configured. "
                "Set AUTHENGINE_CLIENT_ID, AUTHENGINE_CLIENT_SECRET, "
                "and AUTHENGINE_BASE_URL in your .env file."
            )
        if not settings.AUTHENGINE_BASE_URL:
            raise AuthenticationError(
                "AUTHENGINE_BASE_URL is required. "
                "Set it to the root URL of the remote AuthEngine instance "
                "e.g. https://auth.company.com"
            )
        return AuthEngineOAuthStrategy(
            base_url=settings.AUTHENGINE_BASE_URL,
            client_id=settings.AUTHENGINE_CLIENT_ID,
            client_secret=settings.AUTHENGINE_CLIENT_SECRET,
            redirect_uri=settings.AUTHENGINE_REDIRECT_URI,
        )

    raise AuthenticationError(
        f"Unknown OAuth provider: '{provider}'. "
        f"Supported: google, github, microsoft, authengine"
    )
