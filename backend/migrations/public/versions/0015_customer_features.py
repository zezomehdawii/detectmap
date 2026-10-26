"""public: customers.features

Revision ID: 0015_customer_features
Revises: 0014_custom_roles
Create Date: 2026-05-24

Per-customer feature flag map. JSONB so we can grow the set without a
migration each time. The service layer owns the default values and the
allow-list — the column just stores whatever the admin toggles.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015_customer_features"
down_revision: Union[str, None] = "0014_custom_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "customers",
        sa.Column(
            "features",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("customers", "features", schema="public")
