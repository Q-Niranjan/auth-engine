import logging

from auth_engine.external_services.email.base import EmailProvider, EmailProviderConfig
from auth_engine.external_services.email.providers.console import ConsoleEmailProvider
from auth_engine.external_services.email.providers.sendgrid import SendGridEmailProvider
from auth_engine.external_services.email.providers.ses import SESEmailProvider
from auth_engine.external_services.email.providers.smtp import SMTPEmailProvider
from auth_engine.models.email_config import EmailProviderType

logger = logging.getLogger(__name__)


class EmailServiceFactory:
    @staticmethod
    def create(config: EmailProviderConfig) -> EmailProvider:
        provider_type = str(config.provider_type).lower()

        if provider_type == EmailProviderType.SENDGRID.value or provider_type == "sendgrid":
            return SendGridEmailProvider(config)

        if provider_type == EmailProviderType.SES.value or provider_type == "ses":
            return SESEmailProvider(config)

        if provider_type == EmailProviderType.SMTP.value or provider_type == "smtp":
            return SMTPEmailProvider(config)

        logger.warning(f"Unknown provider type: {config.provider_type}. Falling back to Console.")
        return ConsoleEmailProvider()
