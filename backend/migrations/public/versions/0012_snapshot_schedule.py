"""public: app_settings.snapshot_refresh_enabled

Revision ID: 0012_snapshot_schedule
Revises: 0011_audit_and_ldap_groups
Create Date: 2026-05-22

Flag that gates the celerybeat-driven periodic coverage-snapshot capture
across active customers (fills the posture trend without manual snapshots).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_snapshot_schedule"
down_revision: Union[str, None] = "0011_audit_and_ldap_groups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "snapshot_refresh_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("app_settings", "snapshot_refresh_enabled", schema="public")
