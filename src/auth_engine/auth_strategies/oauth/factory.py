"""
OAuthProviderFactory — builds the correct strategy instance based on provider name.

Reads credentials from settings so endpoints don't need to know about config.
"""

from auth_engine.auth_strategies.oauth import (
    BaseOAuthStrategy,
    GitHubOAuthStrategy,
    GoogleOAuthStrategy,
    MicrosoftOAuthStrategy,
)
from auth_engine.core.config import settings
from auth_engine.core.exceptions import AuthenticationError


def get_oauth_strategy(provider: str) -> BaseOAuthStrategy:
    """
    Return a configured OAuth strategy for the given provider name.

    Args:
        provider: One of "google", "github", "microsoft"

    Returns:
        Configured strategy instance

    Raises:
        AuthenticationError: If provider is unknown or not configured
    """
    provider = provider.lower()

    if provider == "google":
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise AuthenticationError("Google OAuth is not configured.")
        return GoogleOAuthStrategy(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
        )

    if provider == "github":
        if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
            raise AuthenticationError("GitHub OAuth is not configured.")
        return GitHubOAuthStrategy(
            client_id=settings.GITHUB_CLIENT_ID,
            client_secret=settings.GITHUB_CLIENT_SECRET,
            redirect_uri=settings.GITHUB_REDIRECT_URI,
        )

    if provider == "microsoft":
        if not settings.MICROSOFT_CLIENT_ID or not settings.MICROSOFT_CLIENT_SECRET:
            raise AuthenticationError("Microsoft OAuth is not configured.")
        return MicrosoftOAuthStrategy(
            client_id=settings.MICROSOFT_CLIENT_ID,
            client_secret=settings.MICROSOFT_CLIENT_SECRET,
            redirect_uri=settings.MICROSOFT_REDIRECT_URI,
        )

    raise AuthenticationError(
        f"Unknown OAuth provider: '{provider}'. " f"Supported providers: google, github, microsoft"
    )
