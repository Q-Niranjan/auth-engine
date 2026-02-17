import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from auth_engine.core.mongodb import mongo_db


class AuditService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.collection = db["audit_logs"]

    async def log(
        self,
        *,
        actor_id: Optional[uuid.UUID] = None,
        action: str,
        resource: str,
        resource_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        target_user_id: Optional[uuid.UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success",
    ) -> None:
        try:
            document = {
                "_id": str(uuid.uuid4()),
                "actor_id": str(actor_id) if actor_id else None,
                "target_user_id": str(target_user_id) if target_user_id else None,
                "tenant_id": str(tenant_id) if tenant_id else None,
                "action": action,
                "resource": resource,
                "resource_id": resource_id,
                "status": status,
                "metadata": metadata or {},
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": datetime.utcnow(),
            }
            await self.collection.insert_one(document)
        except Exception:
            # Non-blocking, best effort logging
            pass
