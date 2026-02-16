import logging

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from auth_engine.core.config import settings

logger = logging.getLogger(__name__)


class MongoDB:
    client: AsyncIOMotorClient = None
    db = None

    async def connect_to_storage(self) -> None:
        logger.info("Connecting to MongoDB...")
        self.client = AsyncIOMotorClient(settings.MONGODB_URL)
        self.db = self.client[settings.MONGODB_DB_NAME]
        logger.info("Connected to MongoDB.")

    async def close_storage_connection(self) -> None:
        logger.info("Closing MongoDB connection...")
        if self.client:
            self.client.close()
        logger.info("MongoDB connection closed.")


mongodb = MongoDB()


async def get_mongodb() -> AsyncIOMotorDatabase:
    return mongodb.db
