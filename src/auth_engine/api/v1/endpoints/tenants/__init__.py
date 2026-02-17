from fastapi import APIRouter

from . import admin

router = APIRouter()

# Tenant endpoints (CRUD, users, roles)
router.include_router(admin.router, tags=["tenants"])
