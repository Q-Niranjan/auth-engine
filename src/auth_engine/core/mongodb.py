from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from auth_engine.core.config import settings

mongo_client: AsyncIOMotorClient | None = None
mongo_db: AsyncIOMotorDatabase | None = None


async def init_mongo() -> None:
    global mongo_client, mongo_db
    mongo_client = AsyncIOMotorClient(settings.MONGODB_URL)
    mongo_db = mongo_client[settings.MONGODB_DB_NAME]


async def close_mongo() -> None:
    if mongo_client:
        mongo_client.close()
