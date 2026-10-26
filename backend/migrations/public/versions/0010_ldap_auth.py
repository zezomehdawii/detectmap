"""public: LDAP/AD auth — app_settings config + users.auth_source

Revision ID: 0010_ldap_auth
Revises: 0009_scheduled_job_runs
Create Date: 2026-05-22

Adds instance-wide LDAP/Active Directory authentication:
- `users.hashed_password` becomes nullable (LDAP users have no local password)
  and gains `auth_source` ('local' | 'ldap').
- `app_settings` gains the LDAP connection/search config. The service-account
  password is Fernet-encrypted (`ldap_bind_password_encrypted`), never plain.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_ldap_auth"
down_revision: Union[str, None] = "0009_scheduled_job_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # users: nullable password + auth source
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(255),
        nullable=True,
        schema="public",
    )
    op.add_column(
        "users",
        sa.Column(
            "auth_source",
            sa.String(10),
            nullable=False,
            server_default="local",
        ),
        schema="public",
    )

    # app_settings: LDAP config
    op.add_column("app_settings", sa.Column("ldap_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")), schema="public")
    op.add_column("app_settings", sa.Column("ldap_host", sa.String(255), nullable=True), schema="public")
    op.add_column("app_settings", sa.Column("ldap_bind_dn", sa.String(500), nullable=True), schema="public")
    op.add_column("app_settings", sa.Column("ldap_bind_password_encrypted", sa.Text(), nullable=True), schema="public")
    op.add_column("app_settings", sa.Column("ldap_user_search_base", sa.String(500), nullable=True), schema="public")
    op.add_column("app_settings", sa.Column("ldap_user_filter", sa.String(300), nullable=False, server_default="(sAMAccountName={username})"), schema="public")
    op.add_column("app_settings", sa.Column("ldap_email_attr", sa.String(80), nullable=False, server_default="mail"), schema="public")
    op.add_column("app_settings", sa.Column("ldap_full_name_attr", sa.String(80), nullable=False, server_default="displayName"), schema="public")
    op.add_column("app_settings", sa.Column("ldap_default_role", sa.String(40), nullable=False, server_default="mssp_readonly"), schema="public")
    op.add_column("app_settings", sa.Column("ldap_start_tls", sa.Boolean(), nullable=False, server_default=sa.text("false")), schema="public")
    op.add_column("app_settings", sa.Column("ldap_verify_cert", sa.Boolean(), nullable=False, server_default=sa.text("true")), schema="public")


def downgrade() -> None:
    for col in (
        "ldap_verify_cert", "ldap_start_tls", "ldap_default_role",
        "ldap_full_name_attr", "ldap_email_attr", "ldap_user_filter",
        "ldap_user_search_base", "ldap_bind_password_encrypted",
        "ldap_bind_dn", "ldap_host", "ldap_enabled",
    ):
        op.drop_column("app_settings", col, schema="public")
    op.drop_column("users", "auth_source", schema="public")
    op.alter_column(
        "users",
        "hashed_password",
        existing_type=sa.String(255),
        nullable=False,
        schema="public",
    )
