import logging
import uuid

from auth_engine.core.security import security
from auth_engine.external_services.email.base import EmailProvider, EmailProviderConfig
from auth_engine.external_services.email.factory import EmailServiceFactory
from auth_engine.repositories.email_config_repo import TenantEmailConfigRepository
from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id
from auth_engine.services.tenant_config_resolver import resolve_config_tenant_id

logger = logging.getLogger(__name__)


class EmailServiceResolver:
    def __init__(self, repository: TenantEmailConfigRepository):
        self.repository = repository

    async def _provider_from_tenant(self, tenant_id: uuid.UUID) -> EmailProvider | None:
        tenant_config_orm = await self.repository.get_by_tenant_id(tenant_id)
        if not tenant_config_orm or not tenant_config_orm.is_active:
            return None

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
            logger.error("Failed to decrypt email credentials for tenant %s: %s", tenant_id, e)
            return None

    async def resolve(self, tenant_id: uuid.UUID | str | None) -> EmailProvider:
        session = self.repository.session
        resolved_id = await resolve_config_tenant_id(session, tenant_id)

        if resolved_id is not None:
            provider = await self._provider_from_tenant(resolved_id)
            if provider is not None:
                return provider

            platform_id = await get_canonical_platform_tenant_id(session)
            if platform_id is not None and platform_id != resolved_id:
                platform_provider = await self._provider_from_tenant(platform_id)
                if platform_provider is not None:
                    return platform_provider

        raise RuntimeError(
            "No email configuration found. "
            "Configure email for the platform tenant in the dashboard."
        )
