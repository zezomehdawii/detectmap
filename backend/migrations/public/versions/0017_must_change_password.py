"""public: users.must_change_password + super_admins.must_change_password

Revision ID: 0017_must_change_password
Revises: 0016_user_preferences
Create Date: 2026-05-24

When the bootstrap / factory-reset script generates a random initial
password for the seed admin, the user must change it on first login.
The login endpoint still issues a token (so the change-password call
can authenticate), but the frontend reads this flag from /auth/me and
forces the user into the change-password screen before anything else.

Defaults to FALSE so existing accounts are unaffected. Cleared on the
first successful /auth/change-password call.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017_must_change_password"
down_revision: Union[str, None] = "0016_user_preferences"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        schema="public",
    )
    op.add_column(
        "super_admins",
        sa.Column(
            "must_change_password",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("super_admins", "must_change_password", schema="public")
    op.drop_column("users", "must_change_password", schema="public")
