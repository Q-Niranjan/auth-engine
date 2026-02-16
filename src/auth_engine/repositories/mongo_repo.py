from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


class MongoRepository:
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str):
        self.db = db
        self.collection = db[collection_name]

    async def find_one(self, filter: dict[str, Any]) -> dict[str, Any] | None:
        return await self.collection.find_one(filter)

    async def insert_one(self, document: dict[str, Any]) -> str:
        result = await self.collection.insert_one(document)
        return str(result.inserted_id)

    async def update_one(self, filter: dict[str, Any], update: dict[str, Any]) -> None:
        await self.collection.update_one(filter, {"$set": update})

    async def delete_one(self, filter: dict[str, Any]) -> None:
        await self.collection.delete_one(filter)
