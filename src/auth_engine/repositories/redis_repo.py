from typing import Any

from redis.asyncio import Redis


class RedisRepository:
    def __init__(self, client: Redis):
        self.client = client

    async def get(self, key: str) -> Any | None:
        return await self.client.get(key)

    async def set(self, key: str, value: Any, expire: int | None = None) -> None:
        await self.client.set(key, value, ex=expire)

    async def delete(self, key: str) -> None:
        await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        return await self.client.exists(key) > 0
