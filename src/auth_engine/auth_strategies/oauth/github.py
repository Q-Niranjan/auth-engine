# auth_strategies/oauth/github.py

import logging
from typing import Any

import httpx

from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy
from auth_engine.core.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class GitHubOAuthStrategy(BaseOAuthStrategy):
    """
    OAuth 2.0 strategy for GitHub login.

    Note: GitHub does NOT support OIDC — it's plain OAuth 2.0.
    The user's primary email may not be in the /user endpoint if it's
    set to private, so we make a separate call to /user/emails.
    """

    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USERINFO_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"
    DEFAULT_SCOPES = ["read:user", "user:email"]

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(
            provider_name="github",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    async def fetch_user_profile(self, access_token: str) -> dict[str, Any]:
        """
        Override to also fetch the primary verified email separately,
        since GitHub users can set their profile email to private.
        """
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            # Fetch main profile
            profile_resp = await client.get(self.USERINFO_URL, headers=headers)
            profile_resp.raise_for_status()
            profile = profile_resp.json()

            # Fetch emails if profile email is null (private accounts)
            if not profile.get("email"):
                try:
                    emails_resp = await client.get(self.EMAILS_URL, headers=headers)
                    emails_resp.raise_for_status()
                    emails = emails_resp.json()

                    # Find the primary verified email
                    primary_email = next(
                        (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                        None,
                    )
                    profile["email"] = primary_email
                except Exception as e:
                    logger.warning(f"[github] Could not fetch user emails: {e}")

            return profile

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Map GitHub's user response to our common format.

        GitHub user fields:
            id         → unique GitHub user ID (integer)
            email      → may be null for private accounts
            name       → full display name
            avatar_url → avatar
            login      → GitHub username
        """
        email = raw_profile.get("email")
        if not email:
            raise AuthenticationError(
                "GitHub account has no verified public email. "
                "Please make your primary email public in GitHub settings, "
                "or use a different login method."
            )

        # Split display name into first/last if possible
        full_name: str = raw_profile.get("name") or raw_profile.get("login") or ""
        name_parts = full_name.split(" ", 1)
        first_name = name_parts[0] if name_parts else None
        last_name = name_parts[1] if len(name_parts) > 1 else None

        return {
            "provider_user_id": str(raw_profile["id"]),
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "avatar_url": raw_profile.get("avatar_url"),
            "provider_name": full_name or raw_profile.get("login"),
        }
