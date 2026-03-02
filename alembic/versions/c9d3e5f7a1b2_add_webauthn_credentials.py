"""add webauthn credentials table

Revision ID: c9d3e5f7a1b2
Revises: b7c2d4e6f8a0
Create Date: 2026-03-03 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "c9d3e5f7a1b2"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "b7c2d4e6f8a0"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create webauthn_credentials table."""
    op.create_table(
        "webauthn_credentials",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Raw authenticator credential ID — variable length bytes, globally unique
        sa.Column("credential_id", sa.LargeBinary, nullable=False, unique=True),
        # CBOR-encoded COSE public key from the authenticator
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        # Authenticator Attestation GUID — identifies the authenticator model
        sa.Column("aaguid", sa.String(64), nullable=False, server_default=""),
        # Monotonic counter for clone detection (0 = counter not supported)
        sa.Column("sign_count", sa.Integer, nullable=False, server_default="0"),
        # User-supplied label (e.g. "MacBook Touch ID")
        sa.Column("device_name", sa.String(255), nullable=False, server_default="My Passkey"),
        # Whether the authenticator performed user verification (biometric/PIN)
        sa.Column("uv_flag", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Index for fast credential lookup by user
    op.create_index(
        "ix_webauthn_credentials_user_id",
        "webauthn_credentials",
        ["user_id"],
    )

    # Unique index on credential_id bytes (already unique=True on column, explicit index for perf)
    op.create_index(
        "ix_webauthn_credentials_credential_id",
        "webauthn_credentials",
        ["credential_id"],
        unique=True,
    )


def downgrade() -> None:
    """Drop webauthn_credentials table."""
    op.drop_index("ix_webauthn_credentials_credential_id", table_name="webauthn_credentials")
    op.drop_index("ix_webauthn_credentials_user_id", table_name="webauthn_credentials")
    op.drop_table("webauthn_credentials")
