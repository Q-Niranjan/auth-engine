import uuid
from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_engine.core.postgres import Base

from enum import Enum
from sqlalchemy import Enum as SAEnum


class RoleScope(str, Enum):
    PLATFORM = "PLATFORM"
    TENANT = "TENANT"


class RoleORM(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    scope: Mapped[RoleScope] = mapped_column(
        SAEnum(RoleScope, name="rolescope"),
        nullable=False
    )
    level: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    permissions = relationship("RolePermissionORM", back_populates="role")
    users = relationship("UserRoleORM", back_populates="role")
