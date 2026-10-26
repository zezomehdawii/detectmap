"""customer profile diagrams (Stage 2)

Revision ID: 0008_customer_diagrams
Revises: 0007_customer_profile
Create Date: 2026-05-24

Per-tenant network-diagram catalogue: image/PDF/binary files attached to
a customer's profile. Bytes live on the filesystem (under
DIAGRAM_STORAGE_ROOT); the row holds only metadata + the relative path.

Design notes:
  - `kind` is denormalised from mime_type at upload time so the UI can
    pick a renderer (`image | pdf | binary`) without re-parsing.
  - `is_primary` flags the profile cover diagram. We don't enforce
    uniqueness in the DB (a transient two-primary state during a swap is
    fine); the API "set primary" path clears the other row first.
  - No FK to anything else — diagrams are pure profile attachments. If
    we ever attach them to assets we'd add a join table separately.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_customer_diagrams"
down_revision: Union[str, None] = "0007_customer_profile"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "customer_diagrams",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "filename",
            sa.String(255),
            nullable=False,
            comment="Original filename as uploaded — used for download Content-Disposition.",
        ),
        sa.Column(
            "stored_path",
            sa.String(500),
            nullable=False,
            comment="Path under DIAGRAM_STORAGE_ROOT, e.g. acme/<uuid>.png.",
        ),
        sa.Column("mime_type", sa.String(120), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column(
            "kind",
            sa.String(10),
            nullable=False,
            comment="image | pdf | binary — drives the frontend renderer.",
        ),
        sa.Column(
            "is_primary",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("uploaded_by_email", sa.String(320)),
        sa.Column(
            "uploaded_at",
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
    op.create_index(
        "ix_customer_diagrams_uploaded_at",
        "customer_diagrams",
        ["uploaded_at"],
    )
    op.create_index(
        "ix_customer_diagrams_kind",
        "customer_diagrams",
        ["kind"],
    )


def downgrade() -> None:
    op.drop_index("ix_customer_diagrams_kind", table_name="customer_diagrams")
    op.drop_index("ix_customer_diagrams_uploaded_at", table_name="customer_diagrams")
    op.drop_table("customer_diagrams")
