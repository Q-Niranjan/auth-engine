from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class EmailProviderConfig:
    provider_type: str
    api_key: str
    from_email: str
    is_active: bool

class EmailProvider(ABC):
    """Abstract base class for email providers."""

    @abstractmethod
    async def send_email(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        """Send an email to a list of recipients."""
        pass
