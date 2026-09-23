"""Add scan_run_id tracking to observations and last_scan_run_id to assets

Revision ID: 002_add_scan_run_tracking
Revises: 001_initial_schema
Create Date: 2026-09-23 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '002_add_scan_run_tracking'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add last_scan_run_id to assets
    op.add_column('assets', sa.Column('last_scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_assets_last_scan_run_id', 'assets', ['last_scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_assets_last_scan_run_id',
        'assets',
        'scan_runs',
        ['last_scan_run_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # 2. Add scan_run_id to dns_records
    op.add_column('dns_records', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_dns_records_scan_run_id', 'dns_records', ['scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_dns_records_scan_run_id',
        'dns_records',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # 3. Add scan_run_id to service_exposures
    op.add_column('service_exposures', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_service_exposures_scan_run_id', 'service_exposures', ['scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_service_exposures_scan_run_id',
        'service_exposures',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # 4. Add scan_run_id to technologies
    op.add_column('technologies', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_technologies_scan_run_id', 'technologies', ['scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_technologies_scan_run_id',
        'technologies',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # 5. Add scan_run_id to subdomain_certificates
    op.add_column('subdomain_certificates', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_subdomain_certificates_scan_run_id', 'subdomain_certificates', ['scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_subdomain_certificates_scan_run_id',
        'subdomain_certificates',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # 6. Add scan_run_id to evidence
    op.add_column('evidence', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.create_index('ix_evidence_scan_run_id', 'evidence', ['scan_run_id'], unique=False)
    op.create_foreign_key(
        'fk_evidence_scan_run_id',
        'evidence',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )


def downgrade() -> None:
    op.drop_constraint('fk_evidence_scan_run_id', 'evidence', type_='foreignkey')
    op.drop_index('ix_evidence_scan_run_id', table_name='evidence')
    op.drop_column('evidence', 'scan_run_id')

    op.drop_constraint('fk_subdomain_certificates_scan_run_id', 'subdomain_certificates', type_='foreignkey')
    op.drop_index('ix_subdomain_certificates_scan_run_id', table_name='subdomain_certificates')
    op.drop_column('subdomain_certificates', 'scan_run_id')

    op.drop_constraint('fk_technologies_scan_run_id', 'technologies', type_='foreignkey')
    op.drop_index('ix_technologies_scan_run_id', table_name='technologies')
    op.drop_column('technologies', 'scan_run_id')

    op.drop_constraint('fk_service_exposures_scan_run_id', 'service_exposures', type_='foreignkey')
    op.drop_index('ix_service_exposures_scan_run_id', table_name='service_exposures')
    op.drop_column('service_exposures', 'scan_run_id')

    op.drop_constraint('fk_dns_records_scan_run_id', 'dns_records', type_='foreignkey')
    op.drop_index('ix_dns_records_scan_run_id', table_name='dns_records')
    op.drop_column('dns_records', 'scan_run_id')

    op.drop_constraint('fk_assets_last_scan_run_id', 'assets', type_='foreignkey')
    op.drop_index('ix_assets_last_scan_run_id', table_name='assets')
    op.drop_column('assets', 'last_scan_run_id')
