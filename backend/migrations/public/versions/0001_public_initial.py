"""initial public schema

Revision ID: 0001_public_initial
Revises:
Create Date: 2026-05-20

Creates the cross-tenant tables in the 'public' schema.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_public_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mssp_orgs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("branding", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        schema="public",
    )

    # create_type=False so before_create on op.create_table below does NOT
    # re-issue CREATE TYPE (which would fail with DuplicateObject after our
    # explicit .create() runs).
    customer_status = postgresql.ENUM(
        "provisioning", "active", "suspended", "archived",
        name="customer_status", create_type=False,
    )
    customer_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "customers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mssp_org_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.mssp_orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("codename", sa.String(32), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("sector", sa.String(80)),
        sa.Column("status", customer_status, nullable=False, server_default="provisioning"),
        sa.Column("branding", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("mssp_org_id", "codename", name="uq_customer_org_codename"),
        schema="public",
    )
    op.create_index("ix_customers_mssp_org_id", "customers", ["mssp_org_id"], schema="public")
    op.create_index("ix_customers_codename", "customers", ["codename"], schema="public")

    user_role = postgresql.ENUM(
        "product_super_admin", "mssp_admin", "mssp_analyst", "mssp_readonly", "customer_user",
        name="user_role", create_type=False,
    )
    user_role.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(200)),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("mssp_org_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.mssp_orgs.id", ondelete="CASCADE")),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.customers.id", ondelete="CASCADE")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("email", name="uq_users_email"),
        schema="public",
    )
    op.create_index("ix_users_email", "users", ["email"], schema="public")
    op.create_index("ix_users_mssp_org_id", "users", ["mssp_org_id"], schema="public")
    op.create_index("ix_users_customer_id", "users", ["customer_id"], schema="public")

    op.create_table(
        "super_admins",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(200)),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        schema="public",
    )

    op.create_table(
        "attack_catalog_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("summary", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_current", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("domain", "version", name="uq_attack_domain_version"),
        schema="public",
    )

    op.create_table(
        "attack_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("parent_technique_id", sa.String(20)),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("tactics", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("platforms", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("data_sources", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_subtechnique", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("deprecated", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("raw_stix", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("domain", "technique_id", name="uq_attack_domain_tid"),
        schema="public",
    )
    op.create_index("ix_attack_techniques_domain", "attack_techniques", ["domain"], schema="public")
    op.create_index("ix_attack_techniques_technique_id", "attack_techniques", ["technique_id"], schema="public")
    op.create_index("ix_attack_techniques_parent", "attack_techniques", ["parent_technique_id"], schema="public")


def downgrade() -> None:
    op.drop_table("attack_techniques", schema="public")
    op.drop_table("attack_catalog_versions", schema="public")
    op.drop_table("super_admins", schema="public")
    op.drop_table("users", schema="public")
    op.drop_table("customers", schema="public")
    op.drop_table("mssp_orgs", schema="public")
    postgresql.ENUM(name="user_role").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="customer_status").drop(op.get_bind(), checkfirst=True)
