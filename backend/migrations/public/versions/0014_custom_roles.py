"""public: custom_roles + users.custom_role_id

Revision ID: 0014_custom_roles
Revises: 0013_mail_config
Create Date: 2026-05-24

MSSP-org-scoped custom roles. Built-in roles (mssp_admin / mssp_analyst /
mssp_readonly / customer_user / product_super_admin) stay immutable — they
are the tested baseline. Custom roles layer on top: an admin defines a
role with any subset of the Permission catalog and assigns it to users.
Permission resolution checks `users.custom_role_id` first and falls back
to the built-in `users.role` enum.

`permissions` is JSONB (a list of permission-key strings, e.g.
["detection:read", "coverage:read"]). Keeping it as a JSON column rather
than a join table avoids a second migration when the Permission enum
gains new values — the validation happens in the service layer against
the current enum.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_custom_roles"
down_revision: Union[str, None] = "0013_mail_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "custom_roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "mssp_org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.mssp_orgs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("key", sa.String(60), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "permissions",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("mssp_org_id", "key", name="uq_custom_role_org_key"),
        schema="public",
    )
    op.add_column(
        "users",
        sa.Column(
            "custom_role_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.custom_roles.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("users", "custom_role_id", schema="public")
    op.drop_table("custom_roles", schema="public")
