from sqlalchemy import text

from auth_engine.core.mongodb import mongodb
from auth_engine.core.postgres import AsyncSessionLocal
from auth_engine.core.redis import redis_client


async def check_postgres() -> None:
    async with AsyncSessionLocal() as session:
        await session.execute(text("SELECT 1"))


async def check_mongodb() -> None:
    await mongodb.client.admin.command("ping")


async def check_redis() -> None:
    if redis_client.client:
        await redis_client.client.ping()
