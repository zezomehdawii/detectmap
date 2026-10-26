"""initial customer schema

Revision ID: 0001_customer_initial
Revises:
Create Date: 2026-05-20

Creates per-tenant tables. search_path is already set to the target
cust_<codename> schema by migrations/customer/env.py before this runs.

Enum types are created locally per schema because Postgres enums live in
a schema. We give them schema-qualified names by creating with schema=None
(default) — they land in whatever search_path's first entry is, which by
env.py setup is the target customer schema.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_customer_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # create_type=False so before_create on op.create_table below does NOT
    # re-issue CREATE TYPE (which would fail with DuplicateObject).
    detection_status = postgresql.ENUM(
        "idea", "in_development", "tuning", "deployed", "gap", "not_applicable",
        name="detection_status", create_type=False,
    )
    detection_status.create(op.get_bind(), checkfirst=True)

    detection_source = postgresql.ENUM(
        "global", "customized", "custom",
        name="detection_source", create_type=False,
    )
    detection_source.create(op.get_bind(), checkfirst=True)

    sigma_level = postgresql.ENUM(
        "informational", "low", "medium", "high", "critical",
        name="sigma_level", create_type=False,
    )
    sigma_level.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sigma_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("sigma_status", sa.String(32)),
        sa.Column("level", sigma_level),
        sa.Column("author", sa.String(200)),
        sa.Column("sigma_references", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("tags", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("logsource", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("detection", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("falsepositives", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("raw_yaml", sa.Text),
        sa.Column("detection_status", detection_status, nullable=False, server_default="idea"),
        sa.Column("source", detection_source, nullable=False, server_default="custom"),
        sa.Column("score_breadth", sa.Integer, nullable=False, server_default="0"),
        sa.Column("score_depth", sa.Integer, nullable=False, server_default="0"),
        sa.Column("upstream_global_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detections_sigma_id", "detections", ["sigma_id"])
    op.create_index("ix_detections_status", "detections", ["detection_status"])
    op.create_index("ix_detections_source", "detections", ["source"])
    op.create_index("ix_detections_upstream", "detections", ["upstream_global_id"])

    op.create_table(
        "detection_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("detection_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("detections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.UniqueConstraint("detection_id", "technique_id", name="uq_det_tech"),
    )
    op.create_index("ix_det_tech_detection_id", "detection_techniques", ["detection_id"])
    op.create_index("ix_det_tech_technique_id", "detection_techniques", ["technique_id"])

    op.create_table(
        "coverage_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("denominator_kind", sa.String(20), nullable=False),
        sa.Column("denominator_ref", sa.String(80)),
        sa.Column("breadth_score", sa.String(2), nullable=False),
        sa.Column("depth_score", sa.String(2), nullable=False),
        sa.Column("posture_grade", sa.String(2), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("notes", sa.Text),
    )


def downgrade() -> None:
    op.drop_table("coverage_snapshots")
    op.drop_table("detection_techniques")
    op.drop_table("detections")
    postgresql.ENUM(name="sigma_level").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="detection_source").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="detection_status").drop(op.get_bind(), checkfirst=True)
