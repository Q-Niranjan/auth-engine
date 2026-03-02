"""add tenant auth config and social providers

Revision ID: b7c2d4e6f8a0
Revises: 0ae45168ff18
Create Date: 2026-03-03 03:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "b7c2d4e6f8a0"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "0ae45168ff18"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""

    # 1. CREATE TABLE tenant_auth_configs
    op.create_table(
        "tenant_auth_configs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
            index=True,
        ),
        sa.Column("allowed_methods", sa.JSON, nullable=False),
        sa.Column("mfa_required", sa.Boolean, default=False, nullable=False),
        sa.Column("password_policy", sa.JSON, default={}, nullable=False),
        sa.Column("session_ttl_seconds", sa.Integer, default=3600, nullable=False),
        sa.Column("allowed_domains", sa.JSON, default=[], nullable=False),
        sa.Column(
            "oidc_client_id",
            UUID(as_uuid=True),
            sa.ForeignKey("oidc_clients.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # 2. CREATE TABLE tenant_social_providers
    op.create_table(
        "tenant_social_providers",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("client_id", sa.String, nullable=False),
        sa.Column("client_secret", sa.String, nullable=False),
        sa.Column("client_secret_prefix", sa.String(20), nullable=False),
        sa.Column("redirect_uri", sa.String(500), nullable=True),
        sa.Column("oidc_discovery_url", sa.String(500), nullable=True),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id", "provider", name="uq_tenant_social_provider"
        ),
    )

    # 3. ALTER TABLE oidc_clients — add tenant_id
    op.add_column(
        "oidc_clients",
        sa.Column(
            "tenant_id",
            UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_oidc_clients_tenant_id", "oidc_clients", ["tenant_id"]
    )

    # 4. ALTER TABLE tenant_sms_configs — add account_sid
    op.add_column(
        "tenant_sms_configs",
        sa.Column("account_sid", sa.String, nullable=True),
    )

    # 5. DATA MIGRATION — seed default auth configs for existing tenants
    op.execute(
        """
        INSERT INTO tenant_auth_configs (
            id, tenant_id, allowed_methods, mfa_required,
            password_policy, session_ttl_seconds, allowed_domains,
            oidc_client_id, created_at, updated_at
        )
        SELECT
            gen_random_uuid(),
            t.id,
            '["email_password","magic_link","google","github","microsoft","authengine"]'::jsonb,
            false,
            '{}'::jsonb,
            3600,
            '[]'::jsonb,
            null,
            now(),
            now()
        FROM tenants t
        WHERE t.id NOT IN (
            SELECT tenant_id FROM tenant_auth_configs
        )
        """
    )


def downgrade() -> None:
    """Downgrade schema."""

    # Remove account_sid from tenant_sms_configs
    op.drop_column("tenant_sms_configs", "account_sid")

    # Remove tenant_id from oidc_clients
    op.drop_index("ix_oidc_clients_tenant_id", table_name="oidc_clients")
    op.drop_column("oidc_clients", "tenant_id")

    # Drop tables
    op.drop_table("tenant_social_providers")
    op.drop_table("tenant_auth_configs")
