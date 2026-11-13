"""Keep tenant workspaces and track managed sample inventory initialization."""
import sqlalchemy as sa
from alembic import op

revision = "0020_tenant_deployments"
down_revision = "0019_deployment_options"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "customers",
        sa.Column("sample_inventory_seeded", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="public",
    )


def downgrade() -> None:
    op.drop_column("customers", "sample_inventory_seeded", schema="public")
