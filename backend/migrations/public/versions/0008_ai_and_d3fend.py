"""AI authoring config (mssp_orgs columns) + D3FEND catalog tables

Revision ID: 0008_ai_and_d3fend
Revises: 0007_app_settings
Create Date: 2026-05-21

Phase 10:
  - `mssp_orgs` gains five columns to hold the MSSP's AI provider config
    (Anthropic by default). The key itself is Fernet-encrypted at write time
    via `app.core.crypto.encrypt`, matching the connector-secrets pattern.
  - Two new public tables for D3FEND defensive techniques, plus the
    ATT&CK technique → D3FEND technique mapping.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_ai_and_d3fend"
down_revision: Union[str, None] = "0007_app_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- AI authoring config on mssp_orgs --------------------------------
    op.add_column(
        "mssp_orgs",
        sa.Column(
            "ai_provider",
            sa.String(20),
            nullable=False,
            server_default="anthropic",
        ),
    )
    op.add_column(
        "mssp_orgs",
        sa.Column("ai_api_key_encrypted", sa.Text, nullable=True),
    )
    op.add_column(
        "mssp_orgs",
        sa.Column(
            "ai_model",
            sa.String(80),
            nullable=False,
            server_default="claude-opus-4-7",
        ),
    )
    op.add_column(
        "mssp_orgs",
        sa.Column(
            "ai_last_used_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "mssp_orgs",
        sa.Column("ai_last_status", sa.String(40), nullable=True),
    )

    # ---- D3FEND catalog -------------------------------------------------
    op.create_table(
        "d3fend_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("d3fend_id", sa.String(40), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("definition", sa.Text),
        sa.Column("parent_d3fend_id", sa.String(40), nullable=True, index=True),
        sa.Column("kind", sa.String(40), nullable=True),
        sa.Column("url", sa.String(500)),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "attack_technique_d3fend",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False, server_default="enterprise"),
        sa.Column("technique_id", sa.String(20), nullable=False, index=True),
        sa.Column("d3fend_id", sa.String(40), nullable=False, index=True),
        sa.Column("relation", sa.String(40), nullable=True),  # e.g. "d3f:detects", "d3f:hardens"
        sa.UniqueConstraint(
            "domain", "technique_id", "d3fend_id", "relation",
            name="uq_attack_d3fend",
        ),
    )

    op.create_table(
        "d3fend_ingest_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("source_url", sa.String(500)),
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
    )

    # ---- schedule flag for D3FEND on app_settings -----------------------
    op.add_column(
        "app_settings",
        sa.Column(
            "d3fend_refresh_enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "d3fend_refresh_cron",
            sa.String(80),
            nullable=False,
            server_default="0 6 1 * *",  # monthly, 1st @ 06:00 UTC
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "d3fend_refresh_cron")
    op.drop_column("app_settings", "d3fend_refresh_enabled")
    op.drop_table("d3fend_ingest_runs")
    op.drop_table("attack_technique_d3fend")
    op.drop_table("d3fend_techniques")
    for col in (
        "ai_last_status",
        "ai_last_used_at",
        "ai_model",
        "ai_api_key_encrypted",
        "ai_provider",
    ):
        op.drop_column("mssp_orgs", col)
