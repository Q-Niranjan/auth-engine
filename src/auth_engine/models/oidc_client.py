import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from auth_engine.core.postgres import Base


class OIDCClientORM(Base):
    __tablename__ = "oidc_clients"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    client_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Tenant linkage — associates this OIDC client with a specific tenant
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Registration details
    client_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    redirect_uris: Mapped[list | None] = mapped_column(JSON, nullable=True)
    response_types: Mapped[list | None] = mapped_column(JSON, nullable=True)
    grant_types: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Client Authentication Method (e.g. client_secret_basic, private_key_jwt, etc.)
    token_endpoint_auth_method: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # For private_key_jwt auth method
    jwks_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Subject Type (public or pairwise)
    subject_type: Mapped[str] = mapped_column(String(50), default="public", nullable=False)
    sector_identifier_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
