"""analyst-confirmed detection ↔ deployed-rule links

Revision ID: 0011_detection_deployment_links
Revises: 0010_cmf_requirements_plan
Create Date: 2026-10-26

The verified-coverage ladder infers "this detection is deployed" from SIEM
metadata and titles. That heuristic is intentionally conservative and can be
wrong in both directions. This table stores the analyst's decision:

  - status='confirmed' — the curated detection and the deployed use-case are
    the same rule. Confirmation is enough evidence even when the heuristic
    would not have matched (for example, the SIEM renamed the rule).
  - status='rejected' — suppress a heuristic match that is not the same rule.

No row means "keep using the automatic heuristic". Both foreign keys cascade
so removing either source row cleans up the decision automatically.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011_detection_deployment_links"
down_revision: Union[str, None] = "0010_cmf_requirements_plan"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detection_deployment_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "deployed_use_case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("deployed_use_cases.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            comment="confirmed | rejected",
        ),
        sa.Column("note", sa.Text),
        sa.Column("created_by_email", sa.String(320)),
        sa.Column("updated_by_email", sa.String(320)),
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
        sa.UniqueConstraint(
            "detection_id",
            "deployed_use_case_id",
            name="uq_detection_deployment_link",
        ),
    )


def downgrade() -> None:
    op.drop_table("detection_deployment_links")
