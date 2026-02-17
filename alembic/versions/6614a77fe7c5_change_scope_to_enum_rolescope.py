import sqlalchemy as sa

from alembic import op

revision = "6614a77fe7c5"  # pragma: allowlist secret
down_revision = "ec0322df5faf"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum type
    role_scope_enum = sa.Enum("PLATFORM", "TENANT", name="rolescope")
    role_scope_enum.create(op.get_bind(), checkfirst=True)

    # Normalize existing data to uppercase (VERY IMPORTANT)
    op.execute("UPDATE roles SET scope = UPPER(scope);")

    # Alter column using explicit cast
    op.alter_column(
        "roles",
        "scope",
        existing_type=sa.VARCHAR(length=50),
        type_=role_scope_enum,
        postgresql_using="scope::rolescope",
        existing_nullable=False,
    )


def downgrade() -> None:
    # Convert back to string
    op.alter_column(
        "roles",
        "scope",
        existing_type=sa.Enum("PLATFORM", "TENANT", name="rolescope"),
        type_=sa.VARCHAR(length=50),
        postgresql_using="scope::text",
        existing_nullable=False,
    )

    # Drop enum type
    role_scope_enum = sa.Enum("PLATFORM", "TENANT", name="rolescope")
    role_scope_enum.drop(op.get_bind(), checkfirst=True)
