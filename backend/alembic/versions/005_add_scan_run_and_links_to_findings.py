"""Add scan_run_id, technology_id, vulnerability_id, finding_type, remediation, risk_factors to findings for Stage 8

Revision ID: 005_add_scan_run_and_links_to_findings
Revises: 004_add_scan_run_to_asset_relationships
Create Date: 2026-09-24 15:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '005_add_scan_run_and_links_to_findings'
down_revision: Union[str, None] = '004_add_scan_run_to_asset_relationships'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add columns to findings
    op.add_column('findings', sa.Column('scan_run_id', sa.Uuid(), nullable=True))
    op.add_column('findings', sa.Column('technology_id', sa.Uuid(), nullable=True))
    op.add_column('findings', sa.Column('vulnerability_id', sa.Uuid(), nullable=True))
    op.add_column('findings', sa.Column('finding_type', sa.String(length=50), nullable=True, server_default='VULNERABILITY'))
    op.add_column('findings', sa.Column('remediation', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('risk_factors', sa.JSON(), nullable=True))
    op.add_column('findings', sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))

    # 2. Indexes
    op.create_index('ix_findings_scan_run_id', 'findings', ['scan_run_id'], unique=False)
    op.create_index('ix_findings_technology_id', 'findings', ['technology_id'], unique=False)
    op.create_index('ix_findings_vulnerability_id', 'findings', ['vulnerability_id'], unique=False)
    op.create_index('ix_findings_finding_type', 'findings', ['finding_type'], unique=False)

    # 3. Foreign keys
    op.create_foreign_key(
        'fk_findings_scan_run_id',
        'findings',
        'scan_runs',
        ['scan_run_id'],
        ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'fk_findings_technology_id',
        'findings',
        'technologies',
        ['technology_id'],
        ['id'],
        ondelete='SET NULL'
    )
    op.create_foreign_key(
        'fk_findings_vulnerability_id',
        'findings',
        'vulnerabilities',
        ['vulnerability_id'],
        ['id'],
        ondelete='SET NULL'
    )

    # 4. Composite unique constraint for idempotency
    try:
        op.create_unique_constraint(
            'uq_investigation_scan_run_finding',
            'findings',
            ['investigation_id', 'scan_run_id', 'asset_id', 'category', 'title']
        )
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_constraint('uq_investigation_scan_run_finding', 'findings', type_='unique')
    except Exception:
        pass

    op.drop_constraint('fk_findings_vulnerability_id', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_technology_id', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_scan_run_id', 'findings', type_='foreignkey')

    op.drop_index('ix_findings_finding_type', table_name='findings')
    op.drop_index('ix_findings_vulnerability_id', table_name='findings')
    op.drop_index('ix_findings_technology_id', table_name='findings')
    op.drop_index('ix_findings_scan_run_id', table_name='findings')

    op.drop_column('findings', 'updated_at')
    op.drop_column('findings', 'risk_factors')
    op.drop_column('findings', 'remediation')
    op.drop_column('findings', 'finding_type')
    op.drop_column('findings', 'vulnerability_id')
    op.drop_column('findings', 'technology_id')
    op.drop_column('findings', 'scan_run_id')
