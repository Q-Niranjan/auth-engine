from sqlalchemy import text

import auth_engine.core.mongodb as mongodb
from auth_engine.core.postgres import AsyncSessionLocal
from auth_engine.core.redis import redis_client


async def check_postgres() -> None:
    async with AsyncSessionLocal() as session:
        await session.execute(text("SELECT 1"))


async def check_mongodb() -> None:
    if not mongodb.mongo_client:
        raise RuntimeError("MongoDB client is not initialized")
    await mongodb.mongo_client.admin.command("ping")


async def check_redis() -> None:
    if not redis_client.client:
        raise RuntimeError("Redis client is not initialized")
    await redis_client.client.ping()
