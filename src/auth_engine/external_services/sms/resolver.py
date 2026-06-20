import logging
import uuid

from auth_engine.core.security import security
from auth_engine.external_services.sms.base import SMSProvider, SMSProviderConfig
from auth_engine.external_services.sms.factory import SMSServiceFactory
from auth_engine.repositories.sms_config_repo import TenantSMSConfigRepository
from auth_engine.services.social_provider_service import get_canonical_platform_tenant_id
from auth_engine.services.tenant_config_resolver import resolve_config_tenant_id

logger = logging.getLogger(__name__)


class SMSServiceResolver:
    def __init__(self, repository: TenantSMSConfigRepository):
        self.repository = repository

    async def _provider_from_tenant(self, tenant_id: uuid.UUID) -> SMSProvider | None:
        tenant_config_orm = await self.repository.get_by_tenant_id(tenant_id)
        if not tenant_config_orm or not tenant_config_orm.is_active:
            return None

        try:
            api_key = security.decrypt_data(tenant_config_orm.encrypted_credentials)
            config = SMSProviderConfig(
                provider_type=tenant_config_orm.provider.value,
                api_key=api_key,
                from_number=tenant_config_orm.from_number,
                is_active=tenant_config_orm.is_active,
                account_sid=tenant_config_orm.account_sid,
            )
            return SMSServiceFactory.create(config)
        except Exception as e:
            logger.error("Failed to decrypt SMS credentials for tenant %s: %s", tenant_id, e)
            return None

    async def resolve(self, tenant_id: uuid.UUID | str | None) -> SMSProvider:
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
            "No SMS configuration found. Configure SMS for the platform tenant in the dashboard."
        )
