import logging

import httpx

from auth_engine.external_services.sms.base import SMSProvider, SMSProviderConfig

logger = logging.getLogger(__name__)


class AndroidGatewaySMSProvider(SMSProvider):
    """SMS provider that uses an Android phone (with a SIM) as the SMS gateway.

    Targets the HTTP API of the open-source "SMS Gateway for Android"
    (https://sms-gate.app / github.com/capcom6/android-sms-gateway). It works in
    any of the app's modes by pointing the base URL at the right host:

    - Local server mode:   http://<phone-lan-ip>:8080
    - Private server mode:  https://<your-host>
    - Cloud mode:           https://api.sms-gate.app/3rdparty/v1

    Credentials/endpoint resolution (per-tenant DB config):
    - Base URL  -> config.account_sid
    - Basic auth -> config.api_key as "username:password" (encrypted at rest)
    """

    def __init__(self, config: SMSProviderConfig) -> None:
        self.base_url = str(config.account_sid or "").rstrip("/")

        username: str | None = None
        password: str | None = None
        if config.api_key and ":" in config.api_key:
            username, password = config.api_key.split(":", 1)

        self.username = username
        self.password = password

        if not self.base_url:
            logger.warning("Android SMS Gateway base URL is not set.")
        if not self.username or not self.password:
            logger.warning("Android SMS Gateway credentials are not set.")

    async def send_sms(self, to_number: str, message: str) -> bool:
        if not self.base_url or not self.username or not self.password:
            logger.error("Cannot send SMS: Android Gateway URL or credentials missing.")
            return False

        url = f"{self.base_url}/message"
        payload = {"message": message, "phoneNumbers": [to_number]}

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    url,
                    json=payload,
                    auth=(self.username, self.password),
                )

            if 200 <= response.status_code < 300:
                logger.info(f"SMS queued successfully via Android Gateway to {to_number}")
                return True

            logger.error(
                f"Android Gateway failed to send SMS to {to_number}. "
                f"Status: {response.status_code}, Body: {response.text}"
            )
            return False

        except Exception as e:
            logger.error(
                f"Error sending SMS via Android Gateway ({url}): {type(e).__name__}: {e!r}"
            )
            return False
