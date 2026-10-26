"""customer.deployed_use_cases

Revision ID: 0005_deployed_use_cases
Revises: 0004_views_outcomes
Create Date: 2026-05-22

Per-tenant table holding detection use-cases that are actually deployed in
the customer's SIEM — imported either live from the connector API or from an
uploaded CSV export. Kept separate from `detections` so production reality
never mutates the curated Sigma catalog. (connector_id, external_id) is
unique so re-imports upsert in place instead of duplicating.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_deployed_use_cases"
down_revision: Union[str, None] = "0004_views_outcomes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "deployed_use_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "connector_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("connectors.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # 'api' = live fetch from the connector; 'csv' = uploaded export.
        sa.Column("import_source", sa.String(10), nullable=False, server_default="api"),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(40)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("query", sa.Text),
        sa.Column(
            "technique_ids",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "raw",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "synced_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
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
        sa.UniqueConstraint("connector_id", "external_id", name="uq_deployed_uc_conn_ext"),
    )


def downgrade() -> None:
    op.drop_table("deployed_use_cases")
