from fastapi import APIRouter

from auth_engine.api.v1.endpoints import platform, tenants
from auth_engine.core.health import check_mongodb, check_postgres, check_redis

api_router = APIRouter()

# Include Platform Router (contains auth and users)
api_router.include_router(platform.router, prefix="/platform")

# Include Tenants Router (Admin & Scoped Auth)
api_router.include_router(tenants.router, prefix="/tenants")


# Add your health check or other v1 endpoints here
@api_router.get("/health")
async def health_check() -> dict[str, str]:
    try:
        await check_postgres()
        await check_mongodb()
        await check_redis()
        return {"status": "healthy"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
