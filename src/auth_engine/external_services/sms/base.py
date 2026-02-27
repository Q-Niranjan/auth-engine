from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SMSProviderConfig:
    provider_type: str
    api_key: str
    from_number: str
    is_active: bool
    account_sid: str | None = None


class SMSProvider(ABC):
    """Abstract base class for SMS providers."""

    @abstractmethod
    async def send_sms(self, to_number: str, message: str) -> bool:
        """Send an SMS to a recipient."""
        pass
