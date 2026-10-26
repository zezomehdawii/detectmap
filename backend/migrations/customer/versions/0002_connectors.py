"""customer.connectors

Revision ID: 0002_connectors
Revises: 0001_customer_initial
Create Date: 2026-05-21

Phase 8: per-tenant connector configuration (Splunk / Sentinel / Elastic).
Credentials are Fernet-encrypted at the application layer before persisting
to `encrypted_config`. Live sync is explicitly out of scope; `last_test_at`
is reserved for the future "Test connection" workflow.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_connectors"
down_revision: Union[str, None] = "0001_customer_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # No schema qualifier — env.py has search_path set to cust_<codename>.
    op.create_table(
        "connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(40), nullable=False),  # splunk|sentinel|elastic
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        # JSONB shape: {<field_name>: <fernet ciphertext>}. We hold the
        # encrypted values inside JSON so we can keep multiple secret fields
        # (e.g. host, hec_token) per connector without an extra schema column.
        sa.Column(
            "encrypted_config",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # Plain-text fields that are *not* secrets (host, index name, etc.).
        sa.Column(
            "config",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("status", sa.String(40), nullable=False, server_default="planned"),
        sa.Column("last_test_at", sa.DateTime(timezone=True)),
        sa.Column("last_test_message", sa.Text),
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
        sa.UniqueConstraint("kind", "label", name="uq_connector_kind_label"),
    )


def downgrade() -> None:
    op.drop_table("connectors")
