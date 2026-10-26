"""public: user_preferences

Revision ID: 0016_user_preferences
Revises: 0015_customer_features
Create Date: 2026-05-24

Per-user preference blob — server-side persistence for UI state that
should roam with the user (color mode, sidebar collapse, table density,
etc.). Single JSONB column so we can grow the allow-list without a
migration each time; the service layer owns the keys + validation.

One row per user. `user_id` is both PK and FK so a user delete cleans
up automatically. Created lazily on first write — absence == defaults.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016_user_preferences"
down_revision: Union[str, None] = "0015_customer_features"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_preferences",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "prefs",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("user_preferences", schema="public")
