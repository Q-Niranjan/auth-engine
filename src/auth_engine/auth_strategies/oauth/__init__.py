from auth_engine.auth_strategies.oauth.base_oauth import BaseOAuthStrategy
from auth_engine.auth_strategies.oauth.github import GitHubOAuthStrategy
from auth_engine.auth_strategies.oauth.google import GoogleOAuthStrategy
from auth_engine.auth_strategies.oauth.microsoft import MicrosoftOAuthStrategy

__all__ = [
    "BaseOAuthStrategy",
    "GoogleOAuthStrategy",
    "GitHubOAuthStrategy",
    "MicrosoftOAuthStrategy",
]
