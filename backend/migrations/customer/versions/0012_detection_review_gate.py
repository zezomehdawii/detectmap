"""detection review lifecycle + deployment approval gate

Revision ID: 0012_detection_review_gate
Revises: 0011_detection_deployment_links
Create Date: 2026-11-02

Adds the editorial state that gates a detection's promotion to `deployed`:

  - `detections.owner` and the current review assignment/decision fields.
  - `detection_review_events`, an append-only audit trail so repeated review
    cycles are visible without replaying the detection row.

Existing rows that are already deployed are backfilled as approved. That
preserves the pre-migration meaning of `deployed`; only new promotions (or
rules edited after approval) require a fresh review.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012_detection_review_gate"
down_revision: Union[str, None] = "0011_detection_deployment_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("detections", sa.Column("owner", sa.String(200)))
    op.add_column(
        "detections",
        sa.Column(
            "review_status",
            sa.String(20),
            nullable=False,
            server_default="draft",
            comment="draft | in_review | approved | changes_requested",
        ),
    )
    op.add_column("detections", sa.Column("reviewer_email", sa.String(320)))
    op.add_column(
        "detections",
        sa.Column("review_requested_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "detections",
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "detections",
        sa.Column("review_due_at", sa.DateTime(timezone=True)),
    )
    op.add_column("detections", sa.Column("review_note", sa.Text))
    op.create_index(
        "ix_detections_review_status", "detections", ["review_status"]
    )

    # A deployed rule was, by definition, accepted for production before this
    # feature existed. Backfill the approval so the new gate does not
    # retroactively invalidate the current coverage picture.
    op.execute(
        """
        UPDATE detections
           SET review_status = 'approved',
               reviewed_at = COALESCE(updated_at, now())
         WHERE detection_status = 'deployed'
        """
    )

    op.create_table(
        "detection_review_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=False),
        sa.Column("to_status", sa.String(20), nullable=False),
        sa.Column("note", sa.Text),
        sa.Column("actor_email", sa.String(320)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("detection_review_events")
    op.drop_index("ix_detections_review_status", table_name="detections")
    op.drop_column("detections", "review_note")
    op.drop_column("detections", "review_due_at")
    op.drop_column("detections", "reviewed_at")
    op.drop_column("detections", "review_requested_at")
    op.drop_column("detections", "reviewer_email")
    op.drop_column("detections", "review_status")
    op.drop_column("detections", "owner")
