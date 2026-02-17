from collections.abc import AsyncGenerator

from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_engine.core.mongodb import mongo_db
from auth_engine.core.postgres import AsyncSessionLocal
from auth_engine.core.redis import redis_client
from auth_engine.services.audit_service import AuditService


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def get_mongodb() -> AsyncIOMotorDatabase:
    if mongo_db is None:
        raise RuntimeError("MongoDB is not initialized")
    return mongo_db


async def get_audit_service() -> AuditService:
    if mongo_db is None:
        raise RuntimeError("MongoDB is not initialized")
    return AuditService(mongo_db)


async def get_redis() -> Redis:
    if redis_client.client is None:
        raise RuntimeError("Redis client is not initialized")
    return redis_client.client
