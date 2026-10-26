"""ATT&CK groups + software + sector_profiles

Revision ID: 0005_groups_software_sectors
Revises: 0004_default_detections
Create Date: 2026-05-21

Phase 4: APT-scoped denominator needs Groups + Software + uses() SROs.
Sector denominator needs a curated sector→techniques mapping.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_groups_software_sectors"
down_revision: Union[str, None] = "0004_default_detections"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("group_id", sa.String(20), nullable=False),  # e.g. G0007
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "aliases",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("url", sa.String(500)),
        sa.Column(
            "raw_stix",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.UniqueConstraint("domain", "group_id", name="uq_attack_domain_gid"),
        schema="public",
    )
    op.create_index(
        "ix_attack_groups_group_id", "attack_groups", ["group_id"], schema="public"
    )

    op.create_table(
        "attack_software",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("software_id", sa.String(20), nullable=False),  # e.g. S0029
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),  # malware/tool
        sa.Column("description", sa.Text),
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("url", sa.String(500)),
        sa.Column(
            "raw_stix",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.UniqueConstraint("domain", "software_id", name="uq_attack_domain_sid"),
        schema="public",
    )
    op.create_index(
        "ix_attack_software_software_id",
        "attack_software",
        ["software_id"],
        schema="public",
    )

    op.create_table(
        "attack_group_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("group_id", sa.String(20), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.UniqueConstraint(
            "domain", "group_id", "technique_id", name="uq_attack_group_tech"
        ),
        schema="public",
    )
    op.create_index(
        "ix_agt_group_id", "attack_group_techniques", ["group_id"], schema="public"
    )
    op.create_index(
        "ix_agt_technique_id",
        "attack_group_techniques",
        ["technique_id"],
        schema="public",
    )

    op.create_table(
        "attack_software_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("software_id", sa.String(20), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.UniqueConstraint(
            "domain", "software_id", "technique_id", name="uq_attack_software_tech"
        ),
        schema="public",
    )
    op.create_index(
        "ix_ast_software_id",
        "attack_software_techniques",
        ["software_id"],
        schema="public",
    )
    op.create_index(
        "ix_ast_technique_id",
        "attack_software_techniques",
        ["technique_id"],
        schema="public",
    )

    op.create_table(
        "attack_group_software",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("group_id", sa.String(20), nullable=False),
        sa.Column("software_id", sa.String(20), nullable=False),
        sa.UniqueConstraint(
            "domain", "group_id", "software_id", name="uq_attack_group_software"
        ),
        schema="public",
    )

    op.create_table(
        "sector_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sector", sa.String(80), nullable=False, unique=True),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "technique_ids",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
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
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("sector_profiles", schema="public")
    op.drop_table("attack_group_software", schema="public")
    op.drop_index("ix_ast_technique_id", table_name="attack_software_techniques", schema="public")
    op.drop_index("ix_ast_software_id", table_name="attack_software_techniques", schema="public")
    op.drop_table("attack_software_techniques", schema="public")
    op.drop_index("ix_agt_technique_id", table_name="attack_group_techniques", schema="public")
    op.drop_index("ix_agt_group_id", table_name="attack_group_techniques", schema="public")
    op.drop_table("attack_group_techniques", schema="public")
    op.drop_index("ix_attack_software_software_id", table_name="attack_software", schema="public")
    op.drop_table("attack_software", schema="public")
    op.drop_index("ix_attack_groups_group_id", table_name="attack_groups", schema="public")
    op.drop_table("attack_groups", schema="public")
