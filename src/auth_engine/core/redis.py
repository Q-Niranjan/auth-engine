import logging

import redis.asyncio as redis

from auth_engine.core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    client: redis.Redis | None = None

    async def connect(self) -> None:
        logger.info("Connecting to Redis...")
        self.client = redis.from_url(
            str(settings.REDIS_URL),
            db=settings.REDIS_DB,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
        logger.info("Connected to Redis.")

    async def disconnect(self) -> None:
        logger.info("Disconnecting from Redis...")
        if self.client:
            await self.client.close()
        logger.info("Redis disconnected.")


redis_client = RedisClient()


async def get_redis() -> redis.Redis:
    if redis_client.client is None:
        raise RuntimeError("Redis client is not initialized")
    return redis_client.client
