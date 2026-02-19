import uuid
from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


class AuditService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.collection = db["audit_logs"]

    async def log(
        self,
        *,
        actor_id: uuid.UUID | None = None,
        action: str,
        resource: str,
        resource_id: str | None = None,
        tenant_id: str | None = None,
        target_user_id: uuid.UUID | None = None,
        metadata: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
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
