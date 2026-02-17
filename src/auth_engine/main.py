import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth_engine.api.v1.router import api_router
from auth_engine.core.bootstrap import seed_super_admin
from auth_engine.core.config import settings
from auth_engine.core.mongodb import close_mongo, init_mongo, mongo_db
from auth_engine.core.postgres import AsyncSessionLocal
from auth_engine.core.rbac_seed import seed_roles
from auth_engine.core.redis import redis_client

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)

# Silence noisy libraries
logging.getLogger("pymongo").setLevel(logging.WARNING)
logging.getLogger("motor").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Starting up AuthEngine...")

    await init_mongo()
    await redis_client.connect()

    # Bootstrap system data
    async with AsyncSessionLocal() as session:
        await seed_roles(session)
        await seed_super_admin(session)

    # Initialize Audit Log Indexes
    if mongo_db is not None:
        collection = mongo_db["audit_logs"]
        await collection.create_index("actor_id")
        await collection.create_index("tenant_id")
        await collection.create_index("created_at")
        await collection.create_index([("tenant_id", 1), ("created_at", -1)])

    yield

    logger.info("Shutting down AuthEngine...")
    await close_mongo()
    await redis_client.disconnect()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    lifespan=lifespan,
)


origins = (
    settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)


app.include_router(api_router, prefix=settings.API_V1_PREFIX)

if __name__ == "__main__":
    uvicorn.run(
        "auth_engine.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
