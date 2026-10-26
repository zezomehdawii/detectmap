"""customer profile: assets + customer_contacts + asset_detections

Revision ID: 0007_customer_profile
Revises: 0006_gap_workflow
Create Date: 2026-05-24

Per-tenant customer profile (Stage 1 — assets, contacts, and the
asset↔detection linkage). Diagrams ship in a follow-up migration.

Design notes:
  - `assets` is flat (no parent/child relations) — keeps CRUD simple
    and matches the operator survey we did before approving this.
  - `criticality` is a 4-tier enum (low / medium / high / critical);
    "flag critical systems" = `WHERE criticality = 'critical'`.
  - `asset_detections` is an explicit many-to-many. Coverage per-asset
    is computed at read time by joining through detections →
    detection_techniques. No denormalised rollup column to keep stale.
  - `tags` is a JSONB string array so we don't need a join table just
    to store ad-hoc labels (e.g. extra IPs, asset-tag numbers).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_customer_profile"
down_revision: Union[str, None] = "0006_gap_workflow"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- assets ----
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("os", sa.String(120)),
        sa.Column("environment", sa.String(20), nullable=False, server_default="production"),
        sa.Column("location", sa.String(200)),
        sa.Column("owner", sa.String(200)),
        sa.Column("business_function", sa.String(200)),
        sa.Column(
            "criticality",
            sa.String(12),
            nullable=False,
            server_default="medium",
            comment="low | medium | high | critical (string for forward compat)",
        ),
        sa.Column("data_classification", sa.String(20)),
        sa.Column(
            "compliance_scope",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
            comment="String array, validated against the framework picker.",
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "tags",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("notes", sa.Text),
        sa.Column(
            "external_id",
            sa.String(120),
            comment="Reserved for future CMDB / ITSM import dedupe.",
        ),
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
    )
    op.create_index("ix_assets_name", "assets", ["name"])
    op.create_index("ix_assets_kind", "assets", ["kind"])
    op.create_index("ix_assets_criticality", "assets", ["criticality"])
    op.create_index("ix_assets_environment", "assets", ["environment"])
    op.create_index("ix_assets_status", "assets", ["status"])
    op.create_index(
        "ix_assets_external_id",
        "assets",
        ["external_id"],
        unique=False,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )

    # ---- asset ↔ detection linkage ----
    op.create_table(
        "asset_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "asset_id", "detection_id", name="uq_asset_detection"
        ),
    )

    # ---- customer contacts ----
    op.create_table(
        "customer_contacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("role", sa.String(120)),
        sa.Column("email", sa.String(320)),
        sa.Column("phone", sa.String(60)),
        sa.Column("office_address", sa.Text),
        sa.Column(
            "is_primary",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
            comment="Highlighted as the first call in the contacts list.",
        ),
        sa.Column("notes", sa.Text),
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
    op.create_index("ix_customer_contacts_name", "customer_contacts", ["name"])


def downgrade() -> None:
    op.drop_index("ix_customer_contacts_name", table_name="customer_contacts")
    op.drop_table("customer_contacts")
    op.drop_table("asset_detections")
    op.drop_index("ix_assets_external_id", table_name="assets")
    op.drop_index("ix_assets_status", table_name="assets")
    op.drop_index("ix_assets_environment", table_name="assets")
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_index("ix_assets_kind", table_name="assets")
    op.drop_index("ix_assets_name", table_name="assets")
    op.drop_table("assets")
