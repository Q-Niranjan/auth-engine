import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


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
    tenant_id: uuid.UUID | None = None
    is_template: bool = False
    template_role_id: uuid.UUID | None = None
    is_protected_tenant_role: bool = False
    is_system_role: bool = False
    is_name_locked: bool = False
    created_at: datetime
    permissions: list[PermissionResponse] = []
    permission_ids: list[uuid.UUID] = []

    model_config = ConfigDict(from_attributes=True)

    @field_validator("permissions", mode="before")
    @classmethod
    def transform_permissions(cls, v: Any) -> Any:
        if isinstance(v, list):
            return [getattr(p, "permission", p) for p in v]
        return v

    @model_validator(mode="after")
    def populate_permission_ids(self) -> "RoleResponse":
        if self.permissions and not self.permission_ids:
            self.permission_ids = [p.id for p in self.permissions]
        return self


class UserRoleResponse(BaseModel):
    role: RoleResponse
    tenant_id: uuid.UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class RoleAssignment(BaseModel):
    role_name: str | None = None
    role_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def require_role_ref(self) -> "RoleAssignment":
        if not self.role_name and not self.role_id:
            raise ValueError("Either role_name or role_id is required")
        return self


class TenantRoleAssignment(BaseModel):
    tenant_id: uuid.UUID
    role_id: uuid.UUID


class RoleCreateRequest(BaseModel):
    name: str
    description: str | None = None
    scope: RoleScope = RoleScope.TENANT
    level: int = 0
    permissions: list[uuid.UUID] = []
    is_template: bool | None = None


class TenantRoleCreateRequest(BaseModel):
    name: str
    description: str | None = None
    level: int = 0
    permissions: list[uuid.UUID] = []


class CloneFromTemplateRequest(BaseModel):
    template_role_id: uuid.UUID
    name: str | None = None


class RoleUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    level: int | None = None
    permissions: list[uuid.UUID] | None = None
