import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from auth_engine.core.config import settings
from auth_engine.core.security import security
from auth_engine.models.email_config import EmailProviderType
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository

logger = logging.getLogger(__name__)


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


class ConsoleEmailProvider(EmailProvider):
    """Console implementation for testing/debugging when no provider is configured."""

    async def send_email(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        logger.info("--- Sending Email (Console Provider) ---")
        logger.info(f"To: {to_emails}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Body: {html_content[:100]}...")  # Log first 100 chars
        logger.info("--------------------------------------")
        return True


class EmailServiceFactory:
    @staticmethod
    def create(config: EmailProviderConfig) -> EmailProvider:
        provider_type = str(config.provider_type).lower()

        if provider_type == EmailProviderType.SENDGRID.value or provider_type == "sendgrid":
            return SendGridEmailProvider(config)

        # Add other providers here (SES, SMTP)

        logger.warning(f"Unknown provider type: {config.provider_type}. Falling back to Console.")
        return ConsoleEmailProvider()


class EmailServiceResolver:
    def __init__(self, repository: TenantEmailConfigRepository):
        self.repository = repository
        # Platform default config
        self.default_config = EmailProviderConfig(
            provider_type=settings.EMAIL_PROVIDER,
            api_key=settings.EMAIL_PROVIDER_API_KEY,
            from_email=settings.EMAIL_SENDER,
            is_active=True,
        )

    async def resolve(self, tenant_id: uuid.UUID | str) -> EmailProvider:
        if isinstance(tenant_id, str):
            try:
                tenant_id = uuid.UUID(tenant_id)
            except ValueError:
                logger.warning(f"Invalid tenant_id format: {tenant_id}. Using default provider.")
                return EmailServiceFactory.create(self.default_config)

        # Fetch tenant specific config
        tenant_config_orm = await self.repository.get_by_tenant_id(tenant_id)

        if tenant_config_orm and tenant_config_orm.is_active:
            # Decrypt credentials
            try:
                # Decrypting strictly inside the resolver as requested
                api_key = security.decrypt_data(tenant_config_orm.encrypted_credentials)

                config = EmailProviderConfig(
                    provider_type=tenant_config_orm.provider.value,
                    api_key=api_key,
                    from_email=tenant_config_orm.from_email,
                    is_active=tenant_config_orm.is_active,
                )
                return EmailServiceFactory.create(config)
            except Exception as e:
                logger.error(f"Failed to decrypt email credentials for tenant {tenant_id}: {e}")
                # Fallback to default if decryption/loading fails

        # Fallback to default
        return EmailServiceFactory.create(self.default_config)
