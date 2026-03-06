from fastapi import APIRouter

from auth_engine.api.v1 import me, oidc, platform, public, system, tenants

api_router = APIRouter()

# System (health, readiness, etc.)
api_router.include_router(system.system.router, tags=["system"])


# Authentication (Public)
api_router.include_router(public.auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(public.magic_link.router, prefix="/auth/magic-link", tags=["auth"])
api_router.include_router(public.mfa.router, prefix="/auth/mfa", tags=["mfa"])
api_router.include_router(
    public.webauthn.router,
    prefix="/auth/webauthn",
    tags=["webauthn"],
)
api_router.include_router(
    me.webauthn.router,
    prefix="/me/webauthn",
    tags=["webauthn"],
)
api_router.include_router(public.oauth.router, prefix="/auth/oauth", tags=["oauth"])
api_router.include_router(public.select_tenant.router, prefix="/auth", tags=["auth-tenant"])


api_router.include_router(platform.service_api_key.router, prefix="/auth", tags=["auth-introspect"])


# Current User Context
api_router.include_router(me.endpoints.router, prefix="/me", tags=["me"])
api_router.include_router(me.mfa.router, prefix="/me/mfa", tags=["mfa"])


# Platform Management (Super Admin Scope)
api_router.include_router(platform.user.router, prefix="/platform", tags=["platform-users"])
api_router.include_router(
    platform.tenant.router, prefix="/platform", tags=["platform-tenants"]
)
api_router.include_router(platform.roles.router, prefix="/platform", tags=["platform-roles"])
api_router.include_router(platform.audit.router, prefix="/platform", tags=["platform-audit"])
api_router.include_router(
    public.introspect.router, prefix="/platform/service-keys", tags=["platform-service-keys"]
)


# Tenant Management
api_router.include_router(tenants.users.router, prefix="/tenants", tags=["tenant-users"])
api_router.include_router(tenants.roles.router, prefix="/tenants", tags=["tenant-roles"])
api_router.include_router(tenants.audit.router, prefix="/tenants", tags=["tenant-audit"])

# Tenant Auth Configuration
api_router.include_router(
    tenants.auth_config.router, prefix="/tenants", tags=["tenant-auth-config"]
)
api_router.include_router(
    tenants.social_providers.router, prefix="/tenants", tags=["tenant-social-providers"]
)

# Tenant Email & SMS Configuration
api_router.include_router(
    tenants.email_config.router, prefix="/tenants", tags=["tenant-email-config"]
)
api_router.include_router(tenants.sms_config.router, prefix="/tenants", tags=["tenant-sms-config"])


api_router.include_router(oidc.authorize.router, prefix="/oidc", tags=["oidc"])
api_router.include_router(oidc.discovery.router, prefix="/oidc", tags=["oidc"])
api_router.include_router(oidc.token.router, prefix="/oidc", tags=["oidc"])
api_router.include_router(oidc.userinfo.router, prefix="/oidc", tags=["oidc"])
api_router.include_router(oidc.register.router, prefix="/oidc", tags=["oidc"])
