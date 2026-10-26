"""customer.gap_comments + gap_ignores

Revision ID: 0006_gap_workflow
Revises: 0005_deployed_use_cases
Create Date: 2026-05-24

Tenant-scoped gap-analysis workflow:
  - gap_comments: free-text thread on a (technique_id, domain). Multiple
    analysts can pile observations onto a gap before/while building a rule.
  - gap_ignores: one active row per (technique_id, domain) marking the gap
    as deliberately accepted with a documented reason (and optional
    expiry). Filters the gap out of the default top-gaps ranking so the
    daily-driver view doesn't keep re-surfacing it.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_gap_workflow"
down_revision: Union[str, None] = "0005_deployed_use_cases"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gap_comments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("technique_id", sa.String(20), nullable=False, index=True),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("author_email", sa.String(320)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_gap_comments_tid_domain",
        "gap_comments",
        ["technique_id", "domain"],
    )

    op.create_table(
        "gap_ignores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("technique_id", sa.String(20), nullable=False, index=True),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("author_email", sa.String(320)),
        sa.Column(
            "ignored_until",
            sa.Date,
            nullable=True,
            comment="If set, ignore expires at this date and the gap re-surfaces.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "technique_id", "domain", name="uq_gap_ignores_technique_domain"
        ),
    )


def downgrade() -> None:
    op.drop_table("gap_ignores")
    op.drop_index("ix_gap_comments_tid_domain", table_name="gap_comments")
    op.drop_table("gap_comments")
