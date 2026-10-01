"""Add category, entity_key, description, evidence_id, evidence_hash, and uniqueness to change_records for Stage 9

Revision ID: 006_add_monitoring_and_change_details
Revises: 005_add_scan_run_and_links_to_findings
Create Date: 2026-10-01 11:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '006_add_monitoring_and_change_details'
down_revision: Union[str, None] = '005_add_scan_run_and_links_to_findings'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add columns to change_records
    op.add_column('change_records', sa.Column('category', sa.String(length=50), nullable=True))
    op.add_column('change_records', sa.Column('entity_key', sa.String(length=255), nullable=True))
    op.add_column('change_records', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('change_records', sa.Column('evidence_id', sa.Uuid(), nullable=True))
    op.add_column('change_records', sa.Column('evidence_hash', sa.String(length=64), nullable=True))

    # 2. Relax asset_id to nullable for investigation-wide or non-asset changes
    try:
        op.alter_column('change_records', 'asset_id', existing_type=sa.Uuid(), nullable=True)
    except Exception:
        pass

    # 3. Create indexes
    op.create_index('ix_change_records_category', 'change_records', ['category'], unique=False)
    op.create_index('ix_change_records_entity_key', 'change_records', ['entity_key'], unique=False)
    op.create_index('ix_change_records_field_name', 'change_records', ['field_name'], unique=False)
    op.create_index('ix_change_records_evidence_id', 'change_records', ['evidence_id'], unique=False)

    # 4. Foreign key to evidence
    op.create_foreign_key(
        'fk_change_records_evidence_id',
        'change_records',
        'evidence',
        ['evidence_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # 5. Composite unique constraint for idempotent comparison
    try:
        op.create_unique_constraint(
            'uq_change_records_comparison',
            'change_records',
            ['investigation_id', 'previous_scan_id', 'current_scan_id', 'change_type', 'field_name', 'entity_key']
        )
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_constraint('uq_change_records_comparison', 'change_records', type_='unique')
    except Exception:
        pass

    op.drop_constraint('fk_change_records_evidence_id', 'change_records', type_='foreignkey')

    op.drop_index('ix_change_records_evidence_id', table_name='change_records')
    op.drop_index('ix_change_records_field_name', table_name='change_records')
    op.drop_index('ix_change_records_entity_key', table_name='change_records')
    op.drop_index('ix_change_records_category', table_name='change_records')

    try:
        op.alter_column('change_records', 'asset_id', existing_type=sa.Uuid(), nullable=False)
    except Exception:
        pass

    op.drop_column('change_records', 'evidence_hash')
    op.drop_column('change_records', 'evidence_id')
    op.drop_column('change_records', 'description')
    op.drop_column('change_records', 'entity_key')
    op.drop_column('change_records', 'category')
