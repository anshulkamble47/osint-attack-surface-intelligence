"""Add ip_observations table for historical scan isolation

Revision ID: 003_add_ip_observations
Revises: 002_add_scan_run_tracking
Create Date: 2026-09-24 11:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '003_add_ip_observations'
down_revision: Union[str, None] = '002_add_scan_run_tracking'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ip_observations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_run_id', sa.Uuid(), nullable=False),
        sa.Column('ip_address_id', sa.Uuid(), nullable=False),
        sa.Column('asn_id', sa.Uuid(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asn_id'], ['asns.id'], name='fk_ip_observations_asn_id', ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['ip_address_id'], ['ip_addresses.id'], name='fk_ip_observations_ip_address_id', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], name='fk_ip_observations_scan_run_id', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_run_id', 'ip_address_id', name='uq_ip_observations_scan_run_ip')
    )
    op.create_index('ix_ip_observations_asn_id', 'ip_observations', ['asn_id'], unique=False)
    op.create_index('ix_ip_observations_ip_address_id', 'ip_observations', ['ip_address_id'], unique=False)
    op.create_index('ix_ip_observations_scan_run_id', 'ip_observations', ['scan_run_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_ip_observations_scan_run_id', table_name='ip_observations')
    op.drop_index('ix_ip_observations_ip_address_id', table_name='ip_observations')
    op.drop_index('ix_ip_observations_asn_id', table_name='ip_observations')
    op.drop_table('ip_observations')
