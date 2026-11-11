"""Persist environment mode and identify managed sample workspaces."""
import sqlalchemy as sa
from alembic import op

revision = "0019_deployment_options"
down_revision = "0018_login_hint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mssp_orgs",
        sa.Column("deployment_mode", sa.String(20), nullable=False, server_default="multi_tenant"),
        schema="public",
    )
    op.add_column(
        "mssp_orgs",
        sa.Column("sample_data_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="public",
    )
    op.add_column("mssp_orgs", sa.Column("single_customer", sa.String(32)), schema="public")
    op.add_column("mssp_orgs", sa.Column("single_real_customer", sa.String(32)), schema="public")
    op.add_column("customers", sa.Column("sample_dataset", sa.String(20)), schema="public")


def downgrade() -> None:
    op.drop_column("customers", "sample_dataset", schema="public")
    for column in ("single_real_customer", "single_customer", "sample_data_enabled", "deployment_mode"):
        op.drop_column("mssp_orgs", column, schema="public")
