import logging

from auth_engine.external_services.sms.base import SMSProvider, SMSProviderConfig
from auth_engine.external_services.sms.providers.console import ConsoleSMSProvider
from auth_engine.external_services.sms.providers.twilio import TwilioSMSProvider

logger = logging.getLogger(__name__)


class SMSServiceFactory:
    @staticmethod
    def create(config: SMSProviderConfig) -> SMSProvider:
        provider_type = str(config.provider_type).lower()

        if provider_type == "twilio":
            return TwilioSMSProvider(config)

        # Add other providers here (SNS, MessageBird, etc.)

        logger.warning(
            f"Unknown SMS provider type: {config.provider_type}. Falling back to Console."
        )
        return ConsoleSMSProvider()
