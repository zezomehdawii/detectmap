"""public: audit_log + LDAP group→role mapping config

Revision ID: 0011_audit_and_ldap_groups
Revises: 0010_ldap_auth
Create Date: 2026-05-22

- New `audit_log` table: append-only trail of admin/settings actions.
- `app_settings` gains `ldap_group_attr` + `ldap_group_mappings` so LDAP/AD
  group membership can drive role assignment at login.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_audit_and_ldap_groups"
down_revision: Union[str, None] = "0010_ldap_auth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("ldap_group_attr", sa.String(80), nullable=False, server_default="memberOf"),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "ldap_group_mappings",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema="public",
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_email", sa.String(320), index=True),
        sa.Column("actor_kind", sa.String(20), nullable=False, server_default="user"),
        sa.Column("action", sa.String(80), nullable=False, index=True),
        sa.Column("target", sa.String(320)),
        sa.Column("detail", sa.Text),
        sa.Column(
            "at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            index=True,
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("audit_log", schema="public")
    op.drop_column("app_settings", "ldap_group_mappings", schema="public")
    op.drop_column("app_settings", "ldap_group_attr", schema="public")
