from fastapi import APIRouter

from auth_engine.api.v1.endpoints import auth, user
from auth_engine.core.health import check_mongodb, check_postgres, check_redis

api_router = APIRouter()

# Include Auth Router
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# Include User Router
api_router.include_router(user.router, prefix="/users", tags=["users"])


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
