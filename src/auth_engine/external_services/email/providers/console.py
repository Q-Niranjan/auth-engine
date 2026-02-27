import logging

from auth_engine.external_services.email.base import EmailProvider

logger = logging.getLogger(__name__)


class ConsoleEmailProvider(EmailProvider):
    """Console implementation for testing/debugging when no provider is configured."""

    async def send_email(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        logger.info("--- Sending Email (Console Provider) ---")
        logger.info(f"To: {to_emails}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Body: {html_content[:100]}...")  # Log first 100 chars
        logger.info("--------------------------------------")
        return True
