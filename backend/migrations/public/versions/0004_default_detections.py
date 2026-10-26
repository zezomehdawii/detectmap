"""default_detections + sigmahq_ingest_runs

Revision ID: 0004_default_detections
Revises: 0003_attack_jsonb_gin
Create Date: 2026-05-20

Phase 3: SigmaHQ ruleset mirror + sync run history.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_default_detections"
down_revision: Union[str, None] = "0003_attack_jsonb_gin"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "default_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("global_id", sa.String(64), nullable=False, unique=True),
        sa.Column("sigma_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("sigma_status", sa.String(32)),
        sa.Column("level", sa.String(32)),
        sa.Column("author", sa.String(200)),
        sa.Column(
            "sigma_references",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "tags",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "logsource",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "detection",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "falsepositives",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("raw_yaml", sa.Text, nullable=False),
        sa.Column("source_path", sa.String(500)),
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
        schema="public",
    )
    op.create_index(
        "ix_default_detections_global_id",
        "default_detections",
        ["global_id"],
        schema="public",
    )
    op.create_index(
        "ix_default_detections_sigma_id",
        "default_detections",
        ["sigma_id"],
        schema="public",
    )
    op.create_index(
        "ix_default_detections_tags_gin",
        "default_detections",
        ["tags"],
        schema="public",
        postgresql_using="gin",
        postgresql_ops={"tags": "jsonb_path_ops"},
    )

    op.create_table(
        "sigmahq_ingest_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ref", sa.String(120), nullable=False),
        sa.Column("commit_sha", sa.String(60)),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "summary",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "is_current",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("sigmahq_ingest_runs", schema="public")
    op.drop_index("ix_default_detections_tags_gin", table_name="default_detections", schema="public")
    op.drop_index("ix_default_detections_sigma_id", table_name="default_detections", schema="public")
    op.drop_index("ix_default_detections_global_id", table_name="default_detections", schema="public")
    op.drop_table("default_detections", schema="public")
