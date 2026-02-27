"""
ServiceApiKey model

External services (YourComapny, ServiceA, ServiceB...) that need to call
/auth/introspect must authenticate themselves using an API key.

This prevents random internet clients from probing the introspect endpoint.

Flow:
    1. Platform Admin creates an API key for "YourComapny" via platform API
    2. YourComapny stores the key securely
    3. YourComapny sends: POST /auth/introspect
       Headers: X-API-Key: <key>
       Body:    { "token": "<user_access_token>" }
    4. AuthEngine validates the API key, then introspects the token
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_engine.core.postgres import Base


class ServiceApiKeyORM(Base):
    __tablename__ = "service_api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Human-readable name of the service this key belongs to
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # The actual key — stored as a SHA-256 hash, never plaintext
    # The raw key is shown once at creation time, then discarded
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    # Key prefix shown in UI (e.g. "ae_sk_a1b2c3...") — safe to display
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)

    # Which tenant this service key is scoped to (optional)
    # If set, introspect calls using this key can only see data for this tenant
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Who created this key
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    tenant = relationship("TenantORM")
    creator = relationship("UserORM", foreign_keys=[created_by])
