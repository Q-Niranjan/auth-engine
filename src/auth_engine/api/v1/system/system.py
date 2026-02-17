from fastapi import APIRouter
from auth_engine.core.config import settings
from auth_engine.core.health import check_mongodb, check_postgres, check_redis

router = APIRouter()

@router.get("/", response_model=dict[str, str])
async def root() -> dict[str, str]:
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": settings.APP_DESCRIPTION,
        "docs": "/docs",
    }

@router.get("/health")
async def health_check() -> dict[str, str]:
    try:
        await check_postgres()
        await check_mongodb()
        await check_redis()
        return {"status": "healthy"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
