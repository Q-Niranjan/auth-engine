import logging
import uuid

from auth_engine.core.config import settings
from auth_engine.core.security import security
from auth_engine.external_services.sms.base import SMSProvider, SMSProviderConfig
from auth_engine.external_services.sms.factory import SMSServiceFactory
from auth_engine.repositories.sms_config_repo import TenantSMSConfigRepository

logger = logging.getLogger(__name__)


class SMSServiceResolver:
    def __init__(self, repository: TenantSMSConfigRepository):
        self.repository = repository

        self.default_config = SMSProviderConfig(
            provider_type=settings.SMS_PROVIDER,
            api_key=settings.SMS_PROVIDER_API_KEY,
            from_number=settings.SMS_SENDER,
            is_active=True,
            account_sid=settings.SMS_PROVIDER_ACCOUNT_SID,
        )

    async def resolve(self, tenant_id: uuid.UUID | str) -> SMSProvider:
        if isinstance(tenant_id, str):
            if tenant_id == "default":
                return SMSServiceFactory.create(self.default_config)
            try:
                tenant_id = uuid.UUID(tenant_id)
            except ValueError:
                logger.warning(f"Invalid tenant_id format: {tenant_id}. Using default provider.")
                return SMSServiceFactory.create(self.default_config)

        tenant_config_orm = await self.repository.get_by_tenant_id(tenant_id)

        if tenant_config_orm and tenant_config_orm.is_active:
            try:
                # Decrypt credentials
                api_key = security.decrypt_data(tenant_config_orm.encrypted_credentials)

                # If Twilio is used, credentials might be a JSON or just the token.
                # Assuming api_key is the Auth Token for now.
                # For more complex cases, we might store JSON in encrypted_credentials.

                config = SMSProviderConfig(
                    provider_type=tenant_config_orm.provider.value,
                    api_key=api_key,
                    from_number=tenant_config_orm.from_number,
                    is_active=tenant_config_orm.is_active,
                    # For Twilio, we'd need account_sid too.
                    # We might need to store this in a separate column or in credentials JSON.
                    # For now, using default account_sid if not in credentials.
                    account_sid=settings.SMS_PROVIDER_ACCOUNT_SID,
                )
                return SMSServiceFactory.create(config)
            except Exception as e:
                logger.error(f"Failed to decrypt SMS credentials for tenant {tenant_id}: {e}")

        return SMSServiceFactory.create(self.default_config)
