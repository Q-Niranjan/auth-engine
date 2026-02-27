import asyncio
import logging

from auth_engine.external_services.sms.base import SMSProvider, SMSProviderConfig

logger = logging.getLogger(__name__)

try:
    from twilio.rest import Client
except ImportError:
    Client = None
    logger.warning("Twilio SDK not installed. TwilioSMSProvider will not function correctly.")


class TwilioSMSProvider(SMSProvider):
    def __init__(self, config: SMSProviderConfig) -> None:
        self.account_sid = config.account_sid
        self.auth_token = config.api_key
        self.from_number = config.from_number

        if not self.account_sid or not self.auth_token:
            logger.warning("Twilio Account SID or Auth Token is not set.")

    async def send_sms(self, to_number: str, message: str) -> bool:
        if Client is None:
            logger.error("Twilio SDK is not installed. Cannot send SMS.")
            return False

        if not self.account_sid or not self.auth_token:
            logger.error("Cannot send SMS: Twilio credentials missing.")
            return False

        try:
            client = Client(self.account_sid, self.auth_token)

            # Determine if we use from_ (phone number) or messaging_service_sid
            send_args = {"body": message, "to": to_number}
            if str(self.from_number).startswith("MG"):
                send_args["messaging_service_sid"] = self.from_number
            else:
                send_args["from_"] = self.from_number

            # Run the synchronous Twilio call in a thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: client.messages.create(**send_args))

            logger.info(f"SMS sent successfully to {to_number}")
            return True

        except Exception as e:
            logger.error(f"Error sending SMS via Twilio: {str(e)}")
            return False
