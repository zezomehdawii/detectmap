"""GRC crosswalk: frameworks + controls + ATT&CK mappings

Revision ID: 0006_grc_crosswalk
Revises: 0005_groups_software_sectors
Create Date: 2026-05-21

Phase 7: a control framework (NIST CSF, ISO 27001, NCA ECC) is a tree of
controls. A control maps to one or more ATT&CK techniques and/or
mitigations. Mappings have a `source` so user edits survive re-seeds.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_grc_crosswalk"
down_revision: Union[str, None] = "0005_groups_software_sectors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "grc_frameworks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(40), nullable=False, unique=True),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("version", sa.String(40)),
        sa.Column("description", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema="public",
    )

    op.create_table(
        "grc_controls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "framework_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.grc_frameworks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_id", sa.String(40), nullable=False),  # e.g. PR.PS-04
        sa.Column("parent_control_id", sa.String(40)),
        sa.Column("family", sa.String(80)),
        sa.Column("name", sa.String(400), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "framework_id", "control_id", name="uq_grc_framework_control"
        ),
        schema="public",
    )
    op.create_index(
        "ix_grc_controls_framework_id",
        "grc_controls",
        ["framework_id"],
        schema="public",
    )

    op.create_table(
        "grc_technique_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.grc_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("technique_id", sa.String(20), nullable=False),
        # 'seeded' rows are owned by the seeder and may be overwritten on re-seed.
        # 'user' rows survive forever — they're authored by an analyst.
        sa.Column("source", sa.String(12), nullable=False, server_default="seeded"),
        sa.Column("rationale", sa.Text),
        sa.Column("author", sa.String(200)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "control_id", "technique_id", name="uq_grc_control_technique"
        ),
        schema="public",
    )
    op.create_index(
        "ix_grc_tm_technique_id",
        "grc_technique_mappings",
        ["technique_id"],
        schema="public",
    )
    op.create_index(
        "ix_grc_tm_source",
        "grc_technique_mappings",
        ["source"],
        schema="public",
    )

    op.create_table(
        "grc_mitigation_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "control_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("public.grc_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("mitigation_id", sa.String(20), nullable=False),
        sa.Column("source", sa.String(12), nullable=False, server_default="seeded"),
        sa.Column("rationale", sa.Text),
        sa.Column("author", sa.String(200)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "control_id", "mitigation_id", name="uq_grc_control_mitigation"
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("grc_mitigation_mappings", schema="public")
    op.drop_index("ix_grc_tm_source", table_name="grc_technique_mappings", schema="public")
    op.drop_index("ix_grc_tm_technique_id", table_name="grc_technique_mappings", schema="public")
    op.drop_table("grc_technique_mappings", schema="public")
    op.drop_index("ix_grc_controls_framework_id", table_name="grc_controls", schema="public")
    op.drop_table("grc_controls", schema="public")
    op.drop_table("grc_frameworks", schema="public")
