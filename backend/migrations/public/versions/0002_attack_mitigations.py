"""attack mitigations + revoked/url columns on techniques

Revision ID: 0002_attack_mitigations
Revises: 0001_public_initial
Create Date: 2026-05-20

Adds `revoked` and `url` columns to attack_techniques, and creates
`attack_mitigations` + `attack_technique_mitigations` tables for the
Phase 2 ATT&CK ingest (mitigations + technique→mitigation relationships).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_attack_mitigations"
down_revision: Union[str, None] = "0001_public_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "attack_techniques",
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        schema="public",
    )
    op.add_column(
        "attack_techniques",
        sa.Column("url", sa.String(500)),
        schema="public",
    )

    op.create_table(
        "attack_mitigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("mitigation_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
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
        sa.UniqueConstraint("domain", "mitigation_id", name="uq_attack_domain_mid"),
        schema="public",
    )
    op.create_index(
        "ix_attack_mitigations_domain", "attack_mitigations", ["domain"], schema="public"
    )
    op.create_index(
        "ix_attack_mitigations_mitigation_id",
        "attack_mitigations",
        ["mitigation_id"],
        schema="public",
    )

    op.create_table(
        "attack_technique_mitigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("mitigation_id", sa.String(20), nullable=False),
        sa.UniqueConstraint(
            "domain",
            "technique_id",
            "mitigation_id",
            name="uq_attack_tech_mit",
        ),
        schema="public",
    )
    op.create_index(
        "ix_attack_tm_domain",
        "attack_technique_mitigations",
        ["domain"],
        schema="public",
    )
    op.create_index(
        "ix_attack_tm_technique_id",
        "attack_technique_mitigations",
        ["technique_id"],
        schema="public",
    )
    op.create_index(
        "ix_attack_tm_mitigation_id",
        "attack_technique_mitigations",
        ["mitigation_id"],
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("attack_technique_mitigations", schema="public")
    op.drop_table("attack_mitigations", schema="public")
    op.drop_column("attack_techniques", "url", schema="public")
    op.drop_column("attack_techniques", "revoked", schema="public")
