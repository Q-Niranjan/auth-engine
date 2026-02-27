import logging

from auth_engine.external_services.sms.base import SMSProvider

logger = logging.getLogger(__name__)


class ConsoleSMSProvider(SMSProvider):
    """Console implementation for testing/debugging when no provider is configured."""

    async def send_sms(self, to_number: str, message: str) -> bool:
        logger.info("--- Sending SMS (Console Provider) ---")
        logger.info(f"To: {to_number}")
        logger.info(f"Message: {message}")
        logger.info("--------------------------------------")
        return True
