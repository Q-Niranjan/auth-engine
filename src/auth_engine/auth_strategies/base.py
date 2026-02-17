# auth_strategies/base.py

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any


class BaseAuthStrategy(ABC):
    """
    Base class for all authentication strategies
    All strategies must implement this interface
    """

    def __init__(self, name: str):
        self.name = name
        self.created_at = datetime.utcnow()

    @abstractmethod
    async def authenticate(self, credentials: dict[str, Any]) -> dict[str, Any]:
        """
        Authenticate user with provided credentials

        Args:
            credentials: Dictionary containing authentication credentials

        Returns:
            Dictionary containing user information and tokens

        Raises:
            AuthenticationError: If authentication fails
        """
        pass

    @abstractmethod
    async def validate(self, token: str) -> dict[str, Any]:
        """
        Validate authentication token

        Args:
            token: Authentication token to validate

        Returns:
            Dictionary containing validated user information

        Raises:
            InvalidTokenError: If token is invalid
        """
        pass

    async def prepare_credentials(self, raw_credentials: dict[str, Any]) -> dict[str, Any]:
        """
        Prepare and sanitize credentials before authentication
        Can be overridden by specific strategies

        Args:
            raw_credentials: Raw credentials from request

        Returns:
            Prepared credentials dictionary
        """
        return raw_credentials

    async def post_authenticate(self, user_data: dict[str, Any]) -> dict[str, Any]:
        """
        Hook called after successful authentication
        Can be used for logging, analytics, etc.

        Args:
            user_data: User data after successful authentication

        Returns:
            Modified user data (if needed)
        """
        return user_data

    def get_strategy_metadata(self) -> dict[str, Any]:
        """
        Get metadata about this strategy

        Returns:
            Dictionary with strategy information
        """
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "requires_password": self.requires_password(),
        }

    def requires_password(self) -> bool:
        """Whether this strategy requires a password"""
        return False


class PasswordBasedStrategy(BaseAuthStrategy):
    """Base class for password-based authentication strategies"""

    def requires_password(self) -> bool:
        return True


class TokenBasedStrategy(BaseAuthStrategy):
    """Base class for token-based authentication strategies"""

    def requires_password(self) -> bool:
        return False
