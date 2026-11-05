"""public: app_settings.show_login_hint

Revision ID: 0018_login_hint
Revises: 0017_must_change_password
Create Date: 2026-11-05

Adds the product-wide switch that controls whether the sign-in page shows
the configured default credentials. Defaults to TRUE so fresh/demo
installations are usable immediately; an administrator can hide the hint
under Settings -> Branding.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018_login_hint"
down_revision: Union[str, None] = "0017_must_change_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "show_login_hint",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("app_settings", "show_login_hint", schema="public")
