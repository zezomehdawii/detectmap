"""GIN indexes on attack_techniques.tactics and .platforms

Revision ID: 0003_attack_jsonb_gin
Revises: 0002_attack_mitigations
Create Date: 2026-05-20

Phase 4's coverage matrix filters by tactic and platform on every cell paint.
With jsonb_path_ops the `tactics @> '["..."]'` and `platforms @> '["..."]'`
predicates land an index scan instead of a sequential one.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0003_attack_jsonb_gin"
down_revision: Union[str, None] = "0002_attack_mitigations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_attack_techniques_tactics_gin "
        "ON public.attack_techniques USING GIN (tactics jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_attack_techniques_platforms_gin "
        "ON public.attack_techniques USING GIN (platforms jsonb_path_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS public.ix_attack_techniques_platforms_gin")
    op.execute("DROP INDEX IF EXISTS public.ix_attack_techniques_tactics_gin")
