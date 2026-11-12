"""Tenant network inventory and explicit collection and detection mappings.

Revision ID: 0015_networks
Revises: 0014_detection_versions
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0015_networks"
down_revision = "0014_detection_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "networks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("location", sa.String(200)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("cidr", name="uq_networks_cidr"),
    )
    op.create_table(
        "network_data_sources",
        sa.Column(
            "network_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("networks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "asset_data_source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("asset_data_sources.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_index(
        "ix_network_data_sources_asset_data_source_id",
        "network_data_sources",
        ["asset_data_source_id"],
    )
    op.create_table(
        "network_detections",
        sa.Column(
            "network_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("networks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_index("ix_network_detections_detection_id", "network_detections", ["detection_id"])


def downgrade() -> None:
    op.drop_table("network_detections")
    op.drop_table("network_data_sources")
    op.drop_table("networks")
