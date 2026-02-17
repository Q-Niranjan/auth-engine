from fastapi import APIRouter

from . import auth, tenant, user

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["platform-auth"])
router.include_router(user.router, prefix="/users", tags=["platform-users"])
router.include_router(tenant.router, prefix="/tenants", tags=["platform-tenants"])
