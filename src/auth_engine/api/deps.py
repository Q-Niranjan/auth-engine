from collections.abc import AsyncGenerator

from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.mongodb import mongodb
from auth_engine.core.postgres import AsyncSessionLocal
from auth_engine.core.redis import redis_client


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def get_mongodb() -> AsyncIOMotorDatabase:
    return mongodb.db


async def get_redis() -> Redis:
    if redis_client.client is None:
        raise RuntimeError("Redis client is not initialized")
    return redis_client.client
