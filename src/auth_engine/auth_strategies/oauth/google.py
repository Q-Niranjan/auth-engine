# auth_strategies/oauth/google.py

from typing import Any

from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy


class GoogleOAuthStrategy(BaseOAuthStrategy):
    """
    OAuth 2.0 / OIDC strategy for Google Sign-In.

    Scopes requested:
        openid  — enables OIDC id_token
        email   — user's email address
        profile — name, picture, locale
    """

    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    DEFAULT_SCOPES = ["openid", "email", "profile"]

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(
            provider_name="google",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Map Google's userinfo response to our common format.

        Google userinfo fields:
            sub      → unique Google user ID
            email
            given_name, family_name
            picture  → avatar URL
            name     → full display name
        """
        return {
            "provider_user_id": str(raw_profile["sub"]),
            "email": raw_profile["email"],
            "first_name": raw_profile.get("given_name"),
            "last_name": raw_profile.get("family_name"),
            "avatar_url": raw_profile.get("picture"),
            "provider_name": raw_profile.get("name"),
        }
