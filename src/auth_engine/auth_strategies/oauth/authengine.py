# auth_strategies/oauth/authengine.py
"""
AuthEngineOAuthStrategy — "Sign in with AuthEngine" federated login.

Treats a remote AuthEngine instance as an OAuth 2.0 / OIDC provider.
Endpoints are resolved from the OIDC discovery document when possible so
auth/api host aliases and redirects are handled correctly.
"""

import logging
from typing import Any

import httpx

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

logger = logging.getLogger(__name__)

_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"


def normalize_authengine_base_url(url: str) -> str:
    """Accept either the API base URL or the OIDC discovery document URL."""
    base = url.strip().rstrip("/")
    if base.lower().endswith(_DISCOVERY_SUFFIX):
        base = base[: -len(_DISCOVERY_SUFFIX)]
    return base.rstrip("/")


def discovery_document_url(base_or_discovery_url: str) -> str:
    raw = base_or_discovery_url.strip().rstrip("/")
    if raw.lower().endswith(_DISCOVERY_SUFFIX):
        return raw
    return f"{normalize_authengine_base_url(raw)}{_DISCOVERY_SUFFIX}"


async def _follow_redirect(url: str) -> str:
    """Resolve nginx/host aliases that 301 to the canonical API host."""
    async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=10.0) as client:
        response = await client.head(url)
        return str(response.url)


def _fallback_endpoints(base_or_discovery_url: str) -> dict[str, str]:
    base = normalize_authengine_base_url(base_or_discovery_url)
    return {
        "authorization_endpoint": f"{base}/api/v1/oidc/authorize",
        "token_endpoint": f"{base}/api/v1/oidc/token",
        "userinfo_endpoint": f"{base}/api/v1/oidc/userinfo",
    }


async def resolve_authengine_endpoints(base_or_discovery_url: str) -> dict[str, str]:
    """Load OIDC endpoints from discovery and follow redirects to canonical URLs."""
    discovery_url = discovery_document_url(base_or_discovery_url)
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=15.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            document = response.json()

        authorization_endpoint = await _follow_redirect(document["authorization_endpoint"])
        token_endpoint = await _follow_redirect(document["token_endpoint"])
        userinfo_endpoint = await _follow_redirect(document["userinfo_endpoint"])

        return {
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
        }
    except Exception as exc:
        logger.warning(
            "[authengine] Discovery lookup failed for %s, using base URL paths: %s",
            discovery_url,
            exc,
        )
        return _fallback_endpoints(base_or_discovery_url)


class AuthEngineOAuthStrategy(BaseOAuthStrategy):
    """OAuth 2.0 / OIDC strategy for another AuthEngine instance."""

    DEFAULT_SCOPES = ["openid", "email", "profile"]

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        authorization_url: str | None = None,
        token_url: str | None = None,
        userinfo_url: str | None = None,
    ):
        base = normalize_authengine_base_url(base_url)
        fallback = _fallback_endpoints(base_url)

        self.AUTHORIZATION_URL = authorization_url or fallback["authorization_endpoint"]
        self.TOKEN_URL = token_url or fallback["token_endpoint"]
        self.USERINFO_URL = userinfo_url or fallback["userinfo_endpoint"]
        self.base_url = base

        super().__init__(
            provider_name=AUTHENGINE_OIDC,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    def normalize_profile(self, raw_profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider_user_id": str(raw_profile[CLAIM_SUB]),
            "email": raw_profile.get(CLAIM_EMAIL),
            "first_name": raw_profile.get(CLAIM_GIVEN_NAME),
            "last_name": raw_profile.get(CLAIM_FAMILY_NAME),
            "avatar_url": raw_profile.get(CLAIM_PICTURE),
            "provider_name": raw_profile.get(CLAIM_NAME),
            "email_verified": raw_profile.get(CLAIM_EMAIL_VERIFIED, False),
        }
