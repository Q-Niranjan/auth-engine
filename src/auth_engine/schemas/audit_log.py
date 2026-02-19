from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AuditLogBase(BaseModel):
    actor_id: UUID | None = None
    target_user_id: UUID | None = None
    tenant_id: str | None = None
    action: str
    resource: str
    resource_id: str | None = None
    metadata: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    status: str = "success"  # success, failure, error


class AuditLogCreate(AuditLogBase):
    pass


class AuditLog(AuditLogBase):
    id: str = Field(..., alias="_id")
    created_at: datetime

    class Config:
        populate_by_name = True
        json_encoders = {datetime: lambda v: v.isoformat()}
