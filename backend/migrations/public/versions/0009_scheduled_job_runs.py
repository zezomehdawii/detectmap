"""public.scheduled_job_runs — celerybeat run history

Revision ID: 0009_scheduled_job_runs
Revises: 0008_ai_and_d3fend
Create Date: 2026-05-22

Phase 10 follow-up: the celerybeat-fired `scheduled_*` tasks record one
row per fire (skipped / ok / error) so the Settings → Schedule UI can show
"last ran X ago · <status>" per job. Kept tiny + append-only; the API only
ever reads the most recent row per job name.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_scheduled_job_runs"
down_revision: Union[str, None] = "0008_ai_and_d3fend"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduled_job_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job", sa.String(60), nullable=False, index=True),
        sa.Column(
            "ran_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # ok | skipped | error
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("detail", sa.Text, nullable=True),
    )
    op.create_index(
        "ix_scheduled_job_runs_job_ran_at",
        "scheduled_job_runs",
        ["job", "ran_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scheduled_job_runs_job_ran_at", table_name="scheduled_job_runs")
    op.drop_table("scheduled_job_runs")
