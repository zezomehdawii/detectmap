"""public: app_settings SMTP / outbound mail config

Revision ID: 0013_mail_config
Revises: 0012_snapshot_schedule
Create Date: 2026-05-22

Instance-wide outbound mail (SMTP) configuration on the app_settings
singleton. The SMTP password is Fernet-encrypted at rest (stored in
mail_password_encrypted), never plain.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013_mail_config"
down_revision: Union[str, None] = "0012_snapshot_schedule"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("mail_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_host", sa.String(length=255), nullable=True),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_port", sa.Integer(), nullable=False, server_default=sa.text("587")),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_username", sa.String(length=320), nullable=True),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_password_encrypted", sa.Text(), nullable=True),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_from_address", sa.String(length=320), nullable=True),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "mail_from_name",
            sa.String(length=120),
            nullable=False,
            server_default="The Detection Map",
        ),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_use_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        schema="public",
    )
    op.add_column(
        "app_settings",
        sa.Column("mail_use_ssl", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        schema="public",
    )


def downgrade() -> None:
    for col in (
        "mail_use_ssl",
        "mail_use_tls",
        "mail_from_name",
        "mail_from_address",
        "mail_password_encrypted",
        "mail_username",
        "mail_port",
        "mail_host",
        "mail_enabled",
    ):
        op.drop_column("app_settings", col, schema="public")
