from enum import Enum
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

class RoleScope(str, Enum):
    PLATFORM = "PLATFORM"
    TENANT = "TENANT"

class PermissionResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None

    model_config = ConfigDict(from_attributes=True)


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    scope: RoleScope | None = None
    level: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserRoleResponse(BaseModel):
    role: RoleResponse
    tenant_id: uuid.UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class RoleAssignment(BaseModel):
    role_name: str
