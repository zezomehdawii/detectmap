"""CMF theory fields, implemented-source links, and canonical source repair.

Revision ID: 0013_cmf_validation_fields
Revises: 0012_detection_review_gate
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013_cmf_validation_fields"
down_revision: Union[str, None] = "0012_detection_review_gate"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_data_sources", sa.Column("kill_chain_phase", sa.Text()))
    op.add_column("asset_data_sources", sa.Column("follow_on_collection", sa.Text()))
    op.add_column(
        "collection_plan_items",
        sa.Column("asset_data_source_id", postgresql.UUID(as_uuid=True)),
    )
    op.create_index("ix_collection_plan_items_asset_data_source_id", "collection_plan_items", ["asset_data_source_id"])
    op.create_foreign_key(
        "fk_collection_plan_items_asset_data_source", "collection_plan_items",
        "asset_data_sources", ["asset_data_source_id"], ["id"], ondelete="SET NULL",
    )
    # Earlier central CMF pickers wrote "Source: Component" into the source
    # column. The embedded component is authoritative, even if an old component
    # value remained after the user changed the picker.
    op.execute(sa.text("""
        UPDATE asset_data_sources
        SET attack_data_component = NULLIF(btrim(substring(attack_data_source FROM position(':' IN attack_data_source) + 1)), ''),
            attack_data_source = NULLIF(btrim(split_part(attack_data_source, ':', 1)), '')
        WHERE position(':' IN attack_data_source) > 0
    """))


def downgrade() -> None:
    op.drop_constraint("fk_collection_plan_items_asset_data_source", "collection_plan_items", type_="foreignkey")
    op.drop_index("ix_collection_plan_items_asset_data_source_id", table_name="collection_plan_items")
    op.drop_column("collection_plan_items", "asset_data_source_id")
    op.drop_column("asset_data_sources", "follow_on_collection")
    op.drop_column("asset_data_sources", "kill_chain_phase")
