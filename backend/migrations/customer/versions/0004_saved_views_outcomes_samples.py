"""customer.saved_views + detection_outcomes + detection_event_samples

Revision ID: 0004_saved_views_outcomes_samples
Revises: 0003_technique_notes
Create Date: 2026-05-21

Three new per-tenant tables landing together to support:
- saved_views: persisted filter/denominator presets for the coverage matrix
  and detections list ("APT29 + finance + windows" style bookmarks).
- detection_outcomes: per-detection FP/TP/inconclusive event outcomes from
  analysts. Feeds the detection-effectiveness loop on the detection drawer.
- detection_event_samples: known-good / known-bad event samples that get
  re-matched against the Sigma rule on each save to catch regressions.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_views_outcomes"
down_revision: Union[str, None] = "0003_technique_notes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "saved_views",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        # kind = which page the view applies to; UI filters by it.
        sa.Column("kind", sa.String(40), nullable=False, index=True),
        sa.Column(
            "payload",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("author_email", sa.String(320)),
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
        sa.UniqueConstraint("kind", "name", name="uq_saved_view_kind_name"),
    )

    op.create_table(
        "detection_outcomes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # tp = true positive (real attack caught), fp = false positive,
        # unsure = inconclusive (e.g. low-confidence alert under triage)
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("reference_url", sa.String(500)),
        sa.Column("author_email", sa.String(320)),
        sa.Column(
            "observed_at",
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
    )

    op.create_table(
        "detection_event_samples",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("label", sa.String(200), nullable=False),
        # positive = the event SHOULD match the rule; negative = should NOT.
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column(
            "event",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("expected_match", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_pass", sa.Boolean),
        sa.Column("last_run_message", sa.Text),
        sa.Column("author_email", sa.String(320)),
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
    )


def downgrade() -> None:
    op.drop_table("detection_event_samples")
    op.drop_table("detection_outcomes")
    op.drop_table("saved_views")
