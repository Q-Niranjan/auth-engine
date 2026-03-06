# auth_strategies/oauth/authengine.py
"""
AuthEngineOAuthStrategy — "Sign in with AuthEngine" federated login.

Treats a remote AuthEngine instance as an OAuth 2.0 / OIDC provider.
Works exactly like Google, GitHub, or Microsoft — same BaseOAuthStrategy
pattern, sync __init__, hardcoded URL paths derived from AUTHENGINE_BASE_URL.

The remote AuthEngine already exposes standard OIDC endpoints at:
    /api/v1/oidc/authorize
    /api/v1/oidc/token
    /api/v1/oidc/userinfo

So no discovery document is needed — we know the paths.

Use cases:
    - Auth-engine frontend app authenticating via a central auth-engine backend
    - Any application registered as an OIDC client on another AuthEngine instance
    - Multi-tenant setups where one AuthEngine federates into another

Configuration (env vars — same pattern as Google):
    AUTHENGINE_BASE_URL      = https://auth.company.com
    AUTHENGINE_CLIENT_ID     = <client_id from /oidc/register on remote>
    AUTHENGINE_CLIENT_SECRET = <client_secret from /oidc/register on remote>
    AUTHENGINE_REDIRECT_URI  = http://localhost:8000/api/v1/auth/oauth/authengine/callback
"""

from typing import Any

from auth_engine.auth_strategies.constants import (
    AUTHENGINE_OIDC,
    CLAIM_EMAIL,
    CLAIM_EMAIL_VERIFIED,
    CLAIM_FAMILY_NAME,
    CLAIM_GIVEN_NAME,
    CLAIM_NAME,
    CLAIM_PICTURE,
    CLAIM_SUB,
)
from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy


class AuthEngineOAuthStrategy(BaseOAuthStrategy):
    """
    OAuth 2.0 / OIDC strategy for another AuthEngine instance.

    URL patterns are derived from AUTHENGINE_BASE_URL at construction time —
    no runtime discovery, no async factory. Same interface as Google/GitHub/Microsoft.

    Example:
        strategy = AuthEngineOAuthStrategy(
            base_url="https://auth.company.com",
            client_id="abc123",
            client_secret="secret",
            redirect_uri="http://localhost:8000/api/v1/auth/oauth/authengine/callback",
        )
    """

    DEFAULT_SCOPES = ["openid", "email", "profile"]

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        """
        Args:
            base_url:      Root URL of the remote AuthEngine instance.
                           e.g. "https://auth.company.com" or "http://localhost:8000"
            client_id:     OIDC client_id obtained from POST /oidc/register on the remote.
            client_secret: OIDC client_secret from the same registration.
            redirect_uri:  Callback URL on THIS AuthEngine instance.
        """
        base = base_url.rstrip("/")

        # Derive all endpoint URLs from the known AuthEngine path structure.
        # These never change across AuthEngine versions — same as Google's hardcoded URLs.
        self.AUTHORIZATION_URL = f"{base}/api/v1/oidc/authorize"
        self.TOKEN_URL = f"{base}/api/v1/oidc/token"
        self.USERINFO_URL = f"{base}/api/v1/oidc/userinfo"

        # Store base_url for display/audit purposes
        self.base_url = base

        super().__init__(
            provider_name=AUTHENGINE_OIDC,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Map AuthEngine's /oidc/userinfo response to our common format.

        AuthEngine userinfo fields (standard OIDC + authengine: prefixed extensions):
            sub                          → stable unique user ID
            email                        → user email
            email_verified               → bool
            given_name                   → first name
            family_name                  → last name
            picture                      → avatar URL
            name                         → full display name
            authengine:username          → username (non-standard)
            authengine:auth_strategies   → list of login methods enabled
            authengine:mfa_enabled       → bool
        """
        return {
            "provider_user_id": str(raw_profile[CLAIM_SUB]),
            "email": raw_profile.get(CLAIM_EMAIL),
            "first_name": raw_profile.get(CLAIM_GIVEN_NAME),
            "last_name": raw_profile.get(CLAIM_FAMILY_NAME),
            "avatar_url": raw_profile.get(CLAIM_PICTURE),
            "provider_name": raw_profile.get(CLAIM_NAME),
            # email_verified from remote — used to skip local verification
            "email_verified": raw_profile.get(CLAIM_EMAIL_VERIFIED, False),
        }