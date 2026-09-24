"""Add scan_run_id and evidence_id to asset_relationships for historical scan isolation

Revision ID: 004_add_scan_run_to_asset_relationships
Revises: 003_add_ip_observations
Create Date: 2026-09-24 14:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '004_add_scan_run_to_asset_relationships'
down_revision: Union[str, None] = '003_add_ip_observations'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add scan_run_id and evidence_id columns to asset_relationships
    op.add_column('asset_relationships', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.add_column('asset_relationships', sa.Column('evidence_id', sa.Uuid(), nullable=True))

    op.create_index('ix_asset_relationships_scan_run_id', 'asset_relationships', ['scan_run_id'], unique=False)
    op.create_index('ix_asset_relationships_evidence_id', 'asset_relationships', ['evidence_id'], unique=False)

    op.create_foreign_key(
        'fk_asset_relationships_scan_run_id',
        'asset_relationships',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'fk_asset_relationships_evidence_id',
        'asset_relationships',
        'evidence',
        ['evidence_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # 2. Update unique constraint to include scan_run_id
    try:
        op.drop_constraint('uq_investigation_asset_relationship', 'asset_relationships', type_='unique')
    except Exception:
        pass

    try:
        op.create_unique_constraint(
            'uq_investigation_scan_run_asset_relationship',
            'asset_relationships',
            ['investigation_id', 'scan_run_id', 'source_asset_id', 'target_asset_id', 'relationship_type']
        )
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_constraint('uq_investigation_scan_run_asset_relationship', 'asset_relationships', type_='unique')
    except Exception:
        pass

    try:
        op.create_unique_constraint(
            'uq_investigation_asset_relationship',
            'asset_relationships',
            ['investigation_id', 'source_asset_id', 'target_asset_id', 'relationship_type']
        )
    except Exception:
        pass

    op.drop_constraint('fk_asset_relationships_evidence_id', 'asset_relationships', type_='foreignkey')
    op.drop_constraint('fk_asset_relationships_scan_run_id', 'asset_relationships', type_='foreignkey')

    op.drop_index('ix_asset_relationships_evidence_id', table_name='asset_relationships')
    op.drop_index('ix_asset_relationships_scan_run_id', table_name='asset_relationships')

    op.drop_column('asset_relationships', 'evidence_id')
    op.drop_column('asset_relationships', 'scan_run_id')
