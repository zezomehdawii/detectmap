"""customer.technique_notes

Revision ID: 0003_technique_notes
Revises: 0002_connectors
Create Date: 2026-05-21

Per-tenant free-text annotations against ATT&CK techniques — used by the
coverage matrix drawer for analyst notes ("covered by EDR baseline outside
Sigma", "marked N/A because no AWS deployment", etc.). One note per
(technique_id, domain) — last write wins.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_technique_notes"
down_revision: Union[str, None] = "0002_connectors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "technique_notes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("technique_id", sa.String(20), nullable=False, index=True),
        sa.Column(
            "domain", sa.String(20), nullable=False, server_default="enterprise"
        ),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("author_email", sa.String(320)),
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
        sa.UniqueConstraint("technique_id", "domain", name="uq_tech_note_id_domain"),
    )


def downgrade() -> None:
    op.drop_table("technique_notes")
