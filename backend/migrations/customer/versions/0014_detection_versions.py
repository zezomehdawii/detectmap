"""Version history for detection use cases.

Revision ID: 0014_detection_versions
Revises: 0013_cmf_validation_fields
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014_detection_versions"
down_revision: Union[str, None] = "0013_cmf_validation_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "detections", sa.Column("version", sa.Integer(), server_default="1", nullable=False)
    )
    op.add_column(
        "detections",
        sa.Column(
            "last_changed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "detection_versions",
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_by_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("changed_by_email", sa.String(320)),
        sa.Column("changed_by_name", sa.String(200)),
        sa.Column("change_reason", sa.Text(), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("changes", postgresql.JSONB(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("detection_versions")
    op.drop_column("detections", "last_changed_at")
    op.drop_column("detections", "version")
