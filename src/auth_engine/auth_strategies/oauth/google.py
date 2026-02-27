# auth_strategies/oauth/google.py

from typing import Any

from auth_engine.auth_strategies.constants import (
    CLAIM_EMAIL,
    CLAIM_FAMILY_NAME,
    CLAIM_GIVEN_NAME,
    CLAIM_NAME,
    CLAIM_PICTURE,
    CLAIM_SUB,
    GOOGLE_AUTHORIZATION_URL,
    GOOGLE_TOKEN_URL,
    GOOGLE_USERINFO_URL,
)
from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy


class GoogleOAuthStrategy(BaseOAuthStrategy):
    """
    OAuth 2.0 / OIDC strategy for Google Sign-In.

    Scopes requested:
        openid  — enables OIDC id_token
        email   — user's email address
        profile — name, picture, locale
    """

    AUTHORIZATION_URL = GOOGLE_AUTHORIZATION_URL
    TOKEN_URL = GOOGLE_TOKEN_URL
    USERINFO_URL = GOOGLE_USERINFO_URL
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
            "provider_user_id": str(raw_profile[CLAIM_SUB]),
            "email": raw_profile[CLAIM_EMAIL],
            "first_name": raw_profile.get(CLAIM_GIVEN_NAME),
            "last_name": raw_profile.get(CLAIM_FAMILY_NAME),
            "avatar_url": raw_profile.get(CLAIM_PICTURE),
            "provider_name": raw_profile.get(CLAIM_NAME),
        }
