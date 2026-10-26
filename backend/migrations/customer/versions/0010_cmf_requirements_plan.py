"""collection management framework: requirements + plan/implementation tracker

Revision ID: 0010_cmf_requirements_plan
Revises: 0009_cmf_collection_sources
Create Date: 2026-06-09

Slice 2 of the CMF — the lifecycle the MSSP works through:

  - `collection_requirements`: the *why* — collection/intel requirements
    developed from TTX, risk management, threat modeling, incidents,
    compliance. Optionally scoped to ATT&CK techniques / an APT group.
  - `collection_plan_items`: the *what* + the implementation *tracker*. Each
    row is a data source to start collecting (seeded from gap analysis or
    added by hand) whose `status` walks proposed → approved → in_progress →
    collected → validated. Optionally links to the driving requirement and a
    target asset.

Both are string-validated (no DB enums) for forward compat, matching the
asset module.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_cmf_requirements_plan"
down_revision: Union[str, None] = "0009_cmf_collection_sources"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "collection_requirements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "driver", sa.String(40), nullable=False, server_default="other",
            comment="ttx | risk_management | threat_modeling | threat_intel | "
            "incident | compliance | other",
        ),
        sa.Column("priority", sa.String(12), nullable=False, server_default="medium"),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="proposed",
            comment="proposed | active | satisfied | archived",
        ),
        sa.Column(
            "attack_technique_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("apt_group_id", sa.String(20)),
        sa.Column("author_email", sa.String(320)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_collection_requirements_title", "collection_requirements", ["title"]
    )
    op.create_index(
        "ix_collection_requirements_driver", "collection_requirements", ["driver"]
    )
    op.create_index(
        "ix_collection_requirements_status", "collection_requirements", ["status"]
    )
    op.create_index(
        "ix_collection_requirements_priority", "collection_requirements", ["priority"]
    )

    op.create_table(
        "collection_plan_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "data_source", sa.String(200), nullable=False,
            comment="ATT&CK data source / component to collect, e.g. Process Creation",
        ),
        sa.Column("title", sa.String(200)),
        sa.Column("rationale", sa.Text),
        sa.Column(
            "requirement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("collection_requirements.id", ondelete="SET NULL"),
            index=True,
        ),
        sa.Column(
            "target_asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="SET NULL"),
            index=True,
        ),
        sa.Column("priority", sa.String(12), nullable=False, server_default="medium"),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="proposed",
            comment="proposed | approved | in_progress | collected | validated | deferred",
        ),
        sa.Column("assigned_to", sa.String(200)),
        sa.Column("due_date", sa.Date),
        sa.Column(
            "technique_count", sa.Integer, nullable=False, server_default="0",
        ),
        sa.Column(
            "source_kind", sa.String(12), nullable=False, server_default="manual",
            comment="gap_seed | manual",
        ),
        sa.Column("notes", sa.Text),
        sa.Column("author_email", sa.String(320)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_collection_plan_items_data_source", "collection_plan_items", ["data_source"]
    )
    op.create_index(
        "ix_collection_plan_items_status", "collection_plan_items", ["status"]
    )
    op.create_index(
        "ix_collection_plan_items_priority", "collection_plan_items", ["priority"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_collection_plan_items_priority", table_name="collection_plan_items"
    )
    op.drop_index(
        "ix_collection_plan_items_status", table_name="collection_plan_items"
    )
    op.drop_index(
        "ix_collection_plan_items_data_source", table_name="collection_plan_items"
    )
    op.drop_table("collection_plan_items")
    op.drop_index(
        "ix_collection_requirements_priority", table_name="collection_requirements"
    )
    op.drop_index(
        "ix_collection_requirements_status", table_name="collection_requirements"
    )
    op.drop_index(
        "ix_collection_requirements_driver", table_name="collection_requirements"
    )
    op.drop_index(
        "ix_collection_requirements_title", table_name="collection_requirements"
    )
    op.drop_table("collection_requirements")
