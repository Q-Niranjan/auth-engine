import logging
import uuid

from auth_engine.core.config import settings
from auth_engine.core.security import security
from auth_engine.external_services.email.base import EmailProvider, EmailProviderConfig
from auth_engine.external_services.email.factory import EmailServiceFactory
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository

logger = logging.getLogger(__name__)


class EmailServiceResolver:
    def __init__(self, repository: TenantEmailConfigRepository):
        self.repository = repository

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

        tenant_config_orm = await self.repository.get_by_tenant_id(tenant_id)

        if tenant_config_orm and tenant_config_orm.is_active:
            try:
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

        return EmailServiceFactory.create(self.default_config)
