from fastapi import APIRouter

from auth_engine.api.v1 import me, platform, public, system, tenants

api_router = APIRouter()

# Public APIs (Authentication)
api_router.include_router(public.auth.router, prefix="/auth", tags=["auth"])

# Me APIs (User Context)
api_router.include_router(me.endpoints.router, prefix="", tags=["me"])

# Platform Management
api_router.include_router(platform.user.router, prefix="/platform/users", tags=["platform-users"])
api_router.include_router(
    platform.tenant.router, prefix="/platform/tenants", tags=["platform-tenants"]
)
api_router.include_router(platform.roles.router, prefix="/platform/roles", tags=["platform-roles"])
api_router.include_router(platform.audit.router, prefix="/platform", tags=["platform-audit"])

# Tenant Management
api_router.include_router(tenants.users.router, prefix="/tenants", tags=["tenant-users"])
api_router.include_router(tenants.roles.router, prefix="/tenants", tags=["tenant-roles"])
api_router.include_router(tenants.audit.router, prefix="/tenants", tags=["tenant-audit"])

# System (health check etc)
api_router.include_router(system.system.router)
