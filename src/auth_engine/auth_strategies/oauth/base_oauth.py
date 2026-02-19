# auth_strategies/oauth/base_oauth.py

import logging
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from auth_engine.auth_strategies.base import TokenBasedStrategy
from auth_engine.core.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class BaseOAuthStrategy(TokenBasedStrategy):
    """
    Base class for all OAuth 2.0 / OIDC social login strategies.

    Each provider (Google, GitHub, Microsoft) subclasses this and only needs
    to define its endpoints and how to extract a normalized user profile from
    the provider's raw response.

    Flow:
        1. get_authorization_url()  — redirect user to provider
        2. authenticate()           — exchange code for tokens, fetch profile
        3. validate()               — validate our own JWT (not the provider token)
    """

    # Subclasses must define these
    AUTHORIZATION_URL: str = ""
    TOKEN_URL: str = ""
    USERINFO_URL: str = ""
    DEFAULT_SCOPES: list[str] = []

    def __init__(
        self,
        provider_name: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        super().__init__(provider_name)
        self.provider_name = provider_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_oauth_client(self) -> AsyncOAuth2Client:
        """Create a fresh async OAuth2 client for this provider."""
        return AsyncOAuth2Client(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
        )

    async def get_authorization_url(self, state: str, tenant_id: str | None = None) -> str:
        """
        Step 1: Generate the URL to redirect the user to the provider's login page.

        Args:
            state:     CSRF protection token (store in Redis before redirecting)
            tenant_id: Optional tenant context (encoded into state or separate param)

        Returns:
            Full authorization URL string
        """
        async with self.get_oauth_client() as client:
            # Build extra params for the authorization request
            extra_params: dict[str, Any] = {}
            if tenant_id:
                # Encode tenant_id into the state so we get it back in the callback
                # Format: "{state}:{tenant_id}"
                state = f"{state}:{tenant_id}"

            uri, _ = client.create_authorization_url(
                self.AUTHORIZATION_URL,
                state=state,
                scope=" ".join(self.DEFAULT_SCOPES),
                **extra_params,
            )
            return uri

    async def exchange_code_for_tokens(self, code: str) -> dict[str, Any]:
        """
        Step 2a: Exchange the authorization code for provider access/id tokens.

        Args:
            code: The authorization code received in the callback

        Returns:
            Token response dict from the provider
        """
        async with self.get_oauth_client() as client:
            try:
                token = await client.fetch_token(
                    self.TOKEN_URL,
                    code=code,
                    grant_type="authorization_code",
                )
                return dict(token)
            except Exception as e:
                logger.error(f"[{self.provider_name}] Token exchange failed: {e}")
                raise AuthenticationError(
                    f"Failed to exchange authorization code with {self.provider_name}"
                ) from e

    async def fetch_user_profile(self, access_token: str) -> dict[str, Any]:
        """
        Step 2b: Use the provider access token to fetch the user's profile.

        Args:
            access_token: The provider's access token

        Returns:
            Raw profile data from provider (provider-specific format)
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self.USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"[{self.provider_name}] UserInfo fetch failed: {e}")
                raise AuthenticationError(
                    f"Failed to fetch user profile from {self.provider_name}"
                ) from e

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize provider-specific profile data into a common format.

        Subclasses MUST override this to map their provider's fields.

        Returns a dict with these guaranteed keys:
            provider_user_id : str   — unique ID from the provider
            email            : str   — user's email
            first_name       : str | None
            last_name        : str | None
            avatar_url       : str | None
            provider_name    : str   — display name from provider
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement normalize_profile()")

    async def authenticate(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """
        Full OAuth authentication flow.

        Expected credentials keys:
            code     : str  — authorization code from provider callback
            (token exchange + profile fetch happens inside)

        Returns:
            dict with keys: provider, provider_user_id, email, first_name,
                           last_name, avatar_url, provider_tokens
        """
        code = credentials.get("code")
        if not code:
            raise AuthenticationError("Authorization code is required")

        # Exchange code → provider tokens
        provider_tokens = await self.exchange_code_for_tokens(code)

        access_token = provider_tokens.get("access_token")
        if not access_token:
            raise AuthenticationError(f"No access token received from {self.provider_name}")

        # Fetch user profile from provider
        raw_profile = await self.fetch_user_profile(access_token)

        # Normalize to common format
        normalized = self.normalize_profile(raw_profile)

        return {
            "provider": self.provider_name,
            "provider_user_id": normalized["provider_user_id"],
            "email": normalized["email"],
            "first_name": normalized.get("first_name"),
            "last_name": normalized.get("last_name"),
            "avatar_url": normalized.get("avatar_url"),
            "provider_name": normalized.get("provider_name"),
            "provider_tokens": {
                "access_token": access_token,
                "refresh_token": provider_tokens.get("refresh_token"),
                "expires_at": provider_tokens.get("expires_at"),
            },
        }

    async def validate(self, token: str) -> dict[str, Any]:
        """
        Validate an AuthEngine JWT (not the provider token).
        This is the same for all OAuth strategies.
        """
        from auth_engine.core.security import token_manager

        try:
            payload = token_manager.verify_access_token(token)
            return payload
        except Exception as e:
            raise AuthenticationError(f"Invalid token: {e}") from e
