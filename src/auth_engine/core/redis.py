import logging

import redis.asyncio as aioredis
import redis

from auth_engine.core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    client: aioredis.Redis | None = None

    async def connect(self) -> None:
        url = str(settings.REDIS_URL)

        self.client = aioredis.from_url(
            url,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
            socket_connect_timeout=10,
            socket_timeout=10,
            socket_keepalive=True,
            retry_on_timeout=True,
            retry_on_error=[
                redis.exceptions.ConnectionError,
                redis.exceptions.TimeoutError,
            ],
            health_check_interval=30,
        )

    async def disconnect(self) -> None:
        if self.client:
            await self.client.aclose()


redis_client = RedisClient()


async def get_redis() -> aioredis.Redis:
    if redis_client.client is None:
        raise RuntimeError("Redis client is not initialized")
    return redis_client.client
