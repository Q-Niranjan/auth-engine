import asyncio
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from auth_engine.services.email.base import EmailProvider, EmailProviderConfig

logger = logging.getLogger(__name__)

class SendGridEmailProvider(EmailProvider):
    def __init__(self, config: EmailProviderConfig) -> None:
        self.api_key = config.api_key
        self.default_sender = config.from_email
        if not self.api_key:
            logger.warning("Email Provider API Key is not set/empty for this provider.")

    async def send_email(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        if not self.api_key:
            logger.error("Cannot send email: API Key is missing.")
            return False

        message = Mail(
            from_email=self.default_sender,
            to_emails=to_emails,
            subject=subject,
            html_content=html_content,
        )

        try:
            sg = SendGridAPIClient(self.api_key)
            # Run the synchronous send call in a thread pool using asyncio.to_thread
            response = await asyncio.to_thread(sg.send, message)

            if 200 <= response.status_code < 300:
                logger.info(f"Email sent successfully to {to_emails}")
                return True
            else:
                logger.error(f"Failed to send email. Status Code: {response.status_code}")
                logger.error(f"Response Body: {response.body}")
                return False

        except Exception as e:
            logger.error(f"Error sending email via SendGrid: {str(e)}")
            return False
