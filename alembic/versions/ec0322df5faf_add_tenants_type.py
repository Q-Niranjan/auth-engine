"""add tenants type

Revision ID: ec0322df5faf
Revises: 7331f6b95d19
Create Date: 2026-02-17 12:23:22.857418

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ec0322df5faf"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "7331f6b95d19"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tenant_type_enum = sa.Enum("PLATFORM", "CUSTOMER", name="tenanttype")

    # Create enum type first
    tenant_type_enum.create(op.get_bind(), checkfirst=True)

    # Then add column
    op.add_column("tenants", sa.Column("type", tenant_type_enum, nullable=False))

    op.alter_column("user_roles", "tenant_id", existing_type=sa.UUID(), nullable=False)

    # ### end Alembic commands ###


def downgrade() -> None:
    op.alter_column("user_roles", "tenant_id", existing_type=sa.UUID(), nullable=True)

    op.drop_column("tenants", "type")

    tenant_type_enum = sa.Enum("PLATFORM", "CUSTOMER", name="tenanttype")

    tenant_type_enum.drop(op.get_bind(), checkfirst=True)
