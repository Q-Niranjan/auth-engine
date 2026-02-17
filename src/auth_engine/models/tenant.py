import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_engine.core.postgres import Base


class TenantType(str, Enum):
    PLATFORM = "PLATFORM"
    CUSTOMER = "CUSTOMER"


class TenantORM(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    type: Mapped[TenantType] = mapped_column(
        SQLEnum(TenantType), default=TenantType.CUSTOMER, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    users = relationship("UserRoleORM", back_populates="tenant")
