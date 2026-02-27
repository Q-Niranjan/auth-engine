from fastapi import APIRouter

from auth_engine.api.v1 import me, platform, public, system, tenants

api_router = APIRouter()

# System (health, readiness, etc.)
api_router.include_router(system.system.router, tags=["system"])


# Authentication (Public)
api_router.include_router(public.auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(public.magic_link.router, prefix="/auth/magic-link", tags=["auth"])
api_router.include_router(public.oauth.router, prefix="/auth/oauth", tags=["oauth"])

api_router.include_router(platform.service_api_key.router, prefix="/auth", tags=["auth-introspect"])


# Current User Context
api_router.include_router(me.endpoints.router, prefix="/me", tags=["me"])


# Platform Management (Super Admin Scope)
api_router.include_router(platform.user.router, prefix="/platform/users", tags=["platform-users"])
api_router.include_router(
    platform.tenant.router, prefix="/platform/tenants", tags=["platform-tenants"]
)
api_router.include_router(platform.roles.router, prefix="/platform/roles", tags=["platform-roles"])
api_router.include_router(platform.audit.router, prefix="/platform/audit", tags=["platform-audit"])
api_router.include_router(
    public.introspect.router, prefix="/platform/service-keys", tags=["platform-service-keys"]
)


# Tenant Management
api_router.include_router(tenants.users.router, prefix="/tenants/users", tags=["tenant-users"])
api_router.include_router(tenants.roles.router, prefix="/tenants/roles", tags=["tenant-roles"])
api_router.include_router(tenants.audit.router, prefix="/tenants/audit", tags=["tenant-audit"])
