import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_engine.core.postgres import Base


class WebAuthnCredentialORM(Base):
    """
    Stores a WebAuthn / Passkey credential registered by a user.

    One user can have multiple credentials (e.g. Touch ID on MacBook,
    Face ID on iPhone, YubiKey). Each is identified by a unique
    credential_id returned by the authenticator during registration.
    """

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Raw credential ID bytes from the authenticator (base64url-encoded when sent over the wire)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)

    # CBOR-encoded public key from the authenticator (stored as raw bytes)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # AAGUID identifies the authenticator model (e.g. YubiKey 5, Touch ID)
    aaguid: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # Monotonically increasing counter to detect cloned authenticators
    sign_count: Mapped[int] = mapped_column(nullable=False, default=0)

    # Human-readable label so users can tell their keys apart
    device_name: Mapped[str] = mapped_column(String(255), nullable=False, default="My Passkey")

    # Whether the credential supports user verification (biometric / PIN)
    uv_flag: Mapped[bool] = mapped_column(nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationship back to user
    user = relationship("UserORM", back_populates="webauthn_credentials")