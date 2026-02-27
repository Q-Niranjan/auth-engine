import uuid
from enum import Enum

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from auth_engine.core.postgres import Base


class SMSProviderType(str, Enum):
    TWILIO = "twilio"
    CONSOLE = "console"


class TenantSMSConfigORM(Base):
    __tablename__ = "tenant_sms_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), unique=True, nullable=False
    )
    provider: Mapped[SMSProviderType] = mapped_column(SQLEnum(SMSProviderType), nullable=False)
    encrypted_credentials: Mapped[str] = mapped_column(String, nullable=False)
    from_number: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
