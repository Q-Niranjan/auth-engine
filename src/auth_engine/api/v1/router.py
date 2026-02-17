from fastapi import APIRouter

from auth_engine.api.v1 import audit, platform, system, tenants

api_router = APIRouter()

api_router.include_router(platform.auth.router, prefix="/platform/auth", tags=["platform"])
api_router.include_router(platform.user.router, prefix="/platform/users", tags=["platform"])
api_router.include_router(platform.tenant.router, prefix="/platform/tenants", tags=["platform"])

api_router.include_router(tenants.management.router, prefix="/tenants/mgmt", tags=["tenants"])
api_router.include_router(tenants.users.router, prefix="/tenants/users", tags=["tenants"])
api_router.include_router(tenants.roles.router, prefix="/tenants/roles", tags=["tenants"])

api_router.include_router(audit.audit_logs.router, prefix="/audit-logs", tags=["Audit Logs"])

# (root and health)
api_router.include_router(system.system.router)
