"""collection management framework: cmf_category + asset_data_sources

Revision ID: 0009_cmf_collection_sources
Revises: 0008_customer_diagrams
Create Date: 2026-06-06

Extends the customer-profile asset inventory into a Collection Management
Framework (CMF). Slice A — the collection-source spine:

  - `assets.cmf_category`: functional/data-domain grouping (endpoint,
    network, identity, cloud, …). Distinct from `business_function`
    (free-text business unit).
  - `asset_data_sources`: one row per data source an asset emits. Holds
    the "what / where stored / how long / quality" of the CMF. The
    `attack_data_source`+`attack_data_component` pair mirrors ATT&CK's
    data-source vocabulary so Phase B can compute visibility coverage
    against `public.attack_techniques.data_sources`. The five `*_q`
    columns are the DeTT&CT data-quality dimensions (0–5, NULL = unscored).

Intelligence requirements and the IR-usage log are separate tables in a
later slice — not created here.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_cmf_collection_sources"
down_revision: Union[str, None] = "0008_customer_diagrams"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "cmf_category",
            sa.String(40),
            comment="endpoint | network | identity | cloud | … (functional grouping)",
        ),
    )
    op.create_index("ix_assets_cmf_category", "assets", ["cmf_category"])

    op.create_table(
        "asset_data_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # What it is
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("attack_data_source", sa.String(120)),
        sa.Column("attack_data_component", sa.String(120)),
        sa.Column(
            "log_source",
            sa.String(200),
            comment="Sigma-style logsource, e.g. windows/security.",
        ),
        sa.Column("description", sa.Text),
        # Where / how long it's stored
        sa.Column(
            "storage_connector_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("connectors.id", ondelete="SET NULL"),
            index=True,
        ),
        sa.Column(
            "storage_location",
            sa.String(200),
            comment="Index / table / path within the platform.",
        ),
        sa.Column("retention_days", sa.Integer),
        # DeTT&CT data-quality dimensions (0–5; NULL = unscored)
        sa.Column("device_completeness_q", sa.Integer),
        sa.Column("data_field_completeness_q", sa.Integer),
        sa.Column("timeliness_q", sa.Integer),
        sa.Column("consistency_q", sa.Integer),
        sa.Column("retention_q", sa.Integer),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("notes", sa.Text),
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
            "asset_id", "name", name="uq_asset_data_source_name"
        ),
    )
    op.create_index(
        "ix_asset_data_sources_attack_data_source",
        "asset_data_sources",
        ["attack_data_source"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_asset_data_sources_attack_data_source",
        table_name="asset_data_sources",
    )
    op.drop_table("asset_data_sources")
    op.drop_index("ix_assets_cmf_category", table_name="assets")
    op.drop_column("assets", "cmf_category")
