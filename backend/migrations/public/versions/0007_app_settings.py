"""public.app_settings — product-wide settings singleton

Revision ID: 0007_app_settings
Revises: 0006_grc_crosswalk
Create Date: 2026-05-21

Phase 8: a single-row settings table for catalog refresh schedule, default
legend overrides, and other product-level toggles. Single-row enforced via
`singleton BOOLEAN PRIMARY KEY DEFAULT TRUE UNIQUE` plus a check constraint
so the API can blindly UPSERT.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_app_settings"
down_revision: Union[str, None] = "0006_grc_crosswalk"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column(
            "singleton",
            sa.Boolean,
            primary_key=True,
            server_default=sa.true(),
        ),
        sa.Column(
            "attack_refresh_enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "attack_refresh_cron",
            sa.String(80),
            nullable=False,
            server_default="0 4 * * 1",
        ),
        sa.Column(
            "sigmahq_refresh_enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "sigmahq_refresh_cron",
            sa.String(80),
            nullable=False,
            server_default="0 5 * * 1",
        ),
        # Legend overrides land here per-state (deployed/idea/gap/...). The UI
        # falls back to the theme defaults when keys are missing.
        sa.Column(
            "legend_overrides",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("singleton = TRUE", name="ck_app_settings_singleton"),
    )

    # Pre-seed the singleton row so PATCH endpoints can always assume it exists.
    op.execute(
        "INSERT INTO public.app_settings (singleton) VALUES (TRUE) ON CONFLICT DO NOTHING"
    )


def downgrade() -> None:
    op.drop_table("app_settings")
