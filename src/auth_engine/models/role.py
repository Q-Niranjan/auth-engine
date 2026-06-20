import uuid
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_engine.core.postgres import Base


class RoleScope(str, Enum):
    PLATFORM = "PLATFORM"
    TENANT = "TENANT"


# Template names whose per-tenant clones cannot be deleted
PROTECTED_TENANT_TEMPLATE_NAMES = frozenset({"TENANT_OWNER"})

PLATFORM_SYSTEM_ROLE_NAMES = frozenset({"SUPER_ADMIN", "PLATFORM_ADMIN"})


class RoleORM(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    scope: Mapped[RoleScope] = mapped_column(SAEnum(RoleScope, name="rolescope"), nullable=False)
    level: Mapped[int] = mapped_column(nullable=False, default=0)

    # NULL = platform role or tenant role template; set = tenant-owned role instance
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    template_role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    permissions = relationship(
        "RolePermissionORM",
        back_populates="role",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    users = relationship(
        "UserRoleORM",
        back_populates="role",
        passive_deletes=True,
    )
    tenant = relationship("TenantORM", foreign_keys=[tenant_id])
    template_role = relationship(
        "RoleORM", remote_side="RoleORM.id", foreign_keys=[template_role_id]
    )

    def _template_role_name_if_loaded(self) -> str | None:
        if "template_role" in sa_inspect(self).unloaded:
            return None
        template_role = self.template_role
        return template_role.name if template_role is not None else None

    @property
    def is_protected_tenant_role(self) -> bool:
        if self.tenant_id is None:
            return False
        template_name = self._template_role_name_if_loaded()
        if template_name is not None:
            return template_name in PROTECTED_TENANT_TEMPLATE_NAMES
        return self.name in PROTECTED_TENANT_TEMPLATE_NAMES

    @property
    def is_system_role(self) -> bool:
        if self.name in PLATFORM_SYSTEM_ROLE_NAMES:
            return True
        if (
            self.tenant_id is None
            and self.is_template
            and self.name in PROTECTED_TENANT_TEMPLATE_NAMES
        ):
            return True
        return self.is_protected_tenant_role

    @property
    def is_name_locked(self) -> bool:
        return self.name in PLATFORM_SYSTEM_ROLE_NAMES
