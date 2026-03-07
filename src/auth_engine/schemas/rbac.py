import uuid
from datetime import datetime
from enum import Enum

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
    permissions: list[str] = []
    permission_ids: list[uuid.UUID] = []

    model_config = ConfigDict(from_attributes=True)


class UserRoleResponse(BaseModel):
    role: RoleResponse
    tenant_id: uuid.UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class RoleAssignment(BaseModel):
    role_name: str
    

class RoleCreateRequest(BaseModel):
    name: str
    description: str | None = None
    scope: RoleScope = RoleScope.TENANT
    level: int = 0
    permissions: list[uuid.UUID] = []


class RoleUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    level: int | None = None
    permissions: list[uuid.UUID] | None = None
