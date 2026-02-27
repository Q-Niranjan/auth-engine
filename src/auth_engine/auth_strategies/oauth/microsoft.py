# auth_strategies/oauth/microsoft.py

from typing import Any

from auth_engine.auth_strategies.constants import (
    MICROSOFT,
    MICROSOFT_AUTHORIZATION_URL,
    MICROSOFT_TOKEN_URL,
    MICROSOFT_USERINFO_URL,
)
from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy


class MicrosoftOAuthStrategy(BaseOAuthStrategy):
    """
    OAuth 2.0 / OIDC strategy for Microsoft (Azure AD / personal accounts).

    Uses the "common" tenant endpoint which supports both:
        - Personal Microsoft accounts (Outlook, Hotmail)
        - Work/school Azure AD accounts (Microsoft 365, Teams)

    To restrict to a specific Azure AD tenant, replace "common" with
    your tenant ID in the URLs.
    """

    # "common" supports both personal and work/school accounts
    AUTHORIZATION_URL = MICROSOFT_AUTHORIZATION_URL
    TOKEN_URL = MICROSOFT_TOKEN_URL
    USERINFO_URL = MICROSOFT_USERINFO_URL
    DEFAULT_SCOPES = ["openid", "email", "profile", "User.Read"]

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(
            provider_name=MICROSOFT,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Map Microsoft Graph /me response to our common format.

        Microsoft Graph fields:
            id                → unique user ID in Microsoft
            mail              → primary email (work accounts)
            userPrincipalName → email fallback (often the UPN = email)
            givenName         → first name
            surname           → last name
            displayName       → full display name
        """
        # Microsoft sometimes puts email in mail, sometimes in userPrincipalName
        email = raw_profile.get("mail") or raw_profile.get("userPrincipalName")

        return {
            "provider_user_id": str(raw_profile["id"]),
            "email": email,
            "first_name": raw_profile.get("givenName"),
            "last_name": raw_profile.get("surname"),
            "avatar_url": None,  # Requires a separate Graph API call with binary response
            "provider_name": raw_profile.get("displayName"),
        }
