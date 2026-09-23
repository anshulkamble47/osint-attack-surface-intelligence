"""Initial Stage 1 schema migration

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-23 21:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # 2. targets table
    op.create_table(
        'targets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('primary_domain', sa.String(length=255), nullable=False),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_authorized', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_targets_primary_domain', 'targets', ['primary_domain'], unique=False)

    # 3. investigations table
    op.create_table(
        'investigations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('reference_code', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending'),
        sa.Column('scan_options', sa.JSON(), nullable=False),
        sa.Column('created_by_id', sa.Uuid(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_investigations_reference_code', 'investigations', ['reference_code'], unique=True)
    op.create_index('ix_investigations_status', 'investigations', ['status'], unique=False)
    op.create_index('ix_investigations_target_id', 'investigations', ['target_id'], unique=False)

    # 4. scan_runs table
    op.create_table(
        'scan_runs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('run_number', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='running'),
        sa.Column('total_discovered_assets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_resolving_assets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_runs_investigation_id', 'scan_runs', ['investigation_id'], unique=False)
    op.create_index('ix_scan_runs_status', 'scan_runs', ['status'], unique=False)

    # 5. assets table (Core Registry)
    op.create_table(
        'assets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('asset_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_assets_asset_type', 'assets', ['asset_type'], unique=False)
    op.create_index('ix_assets_investigation_id', 'assets', ['investigation_id'], unique=False)
    op.create_index('ix_assets_is_active', 'assets', ['is_active'], unique=False)
    op.create_index('ix_assets_target_id', 'assets', ['target_id'], unique=False)
    op.create_index('ix_assets_value', 'assets', ['value'], unique=False)

    # 6. domains table
    op.create_table(
        'domains',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('domain_name', sa.String(length=255), nullable=False),
        sa.Column('registrar', sa.String(length=255), nullable=True),
        sa.Column('registration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expiration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('nameservers', sa.JSON(), nullable=False),
        sa.Column('status', sa.JSON(), nullable=False),
        sa.Column('rdap_raw', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id'),
    )
    op.create_index('ix_domains_domain_name', 'domains', ['domain_name'], unique=True)

    # 7. subdomains table
    op.create_table(
        'subdomains',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('domain_id', sa.Uuid(), nullable=False),
        sa.Column('subdomain_name', sa.String(length=255), nullable=False),
        sa.Column('is_resolving', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('discovery_source', sa.String(length=100), nullable=False, server_default='crt.sh'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id'),
    )
    op.create_index('ix_subdomains_domain_id', 'subdomains', ['domain_id'], unique=False)
    op.create_index('ix_subdomains_is_resolving', 'subdomains', ['is_resolving'], unique=False)
    op.create_index('ix_subdomains_subdomain_name', 'subdomains', ['subdomain_name'], unique=False)

    # 8. dns_records table
    op.create_table(
        'dns_records',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('subdomain_id', sa.Uuid(), nullable=False),
        sa.Column('record_type', sa.String(length=10), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=True),
        sa.Column('resolver', sa.String(length=100), nullable=False, server_default='system_resolver'),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dns_records_record_type', 'dns_records', ['record_type'], unique=False)
    op.create_index('ix_dns_records_subdomain_id', 'dns_records', ['subdomain_id'], unique=False)

    # 9. asns table
    op.create_table(
        'asns',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asn_number', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('country', sa.String(length=10), nullable=True),
        sa.Column('allocated_prefix', sa.String(length=100), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_asns_asn_number', 'asns', ['asn_number'], unique=True)

    # 10. ip_addresses table
    op.create_table(
        'ip_addresses',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('ip_version', sa.Integer(), nullable=False, server_default='4'),
        sa.Column('reverse_dns', sa.String(length=255), nullable=True),
        sa.Column('asn_id', sa.Uuid(), nullable=True),
        sa.Column('country', sa.String(length=10), nullable=True),
        sa.Column('region', sa.String(length=100), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.ForeignKeyConstraint(['asn_id'], ['asns.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('asset_id'),
    )
    op.create_index('ix_ip_addresses_asn_id', 'ip_addresses', ['asn_id'], unique=False)
    op.create_index('ix_ip_addresses_ip_address', 'ip_addresses', ['ip_address'], unique=True)

    # 11. service_exposures table
    op.create_table(
        'service_exposures',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=10), nullable=False, server_default='tcp'),
        sa.Column('service_name', sa.String(length=50), nullable=False, server_default='http'),
        sa.Column('http_status', sa.Integer(), nullable=True),
        sa.Column('page_title', sa.Text(), nullable=True),
        sa.Column('tls_version', sa.String(length=50), nullable=True),
        sa.Column('security_headers', sa.JSON(), nullable=False),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_service_exposures_asset_id', 'service_exposures', ['asset_id'], unique=False)
    op.create_index('ix_service_exposures_port', 'service_exposures', ['port'], unique=False)

    # 12. certificates table
    op.create_table(
        'certificates',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('fingerprint_sha256', sa.String(length=64), nullable=False),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('subject_cn', sa.String(length=255), nullable=False),
        sa.Column('issuer', sa.String(length=255), nullable=False),
        sa.Column('san_list', sa.JSON(), nullable=False),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_to', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_expired', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('ct_log_id', sa.String(length=100), nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_certificates_fingerprint_sha256', 'certificates', ['fingerprint_sha256'], unique=True)
    op.create_index('ix_certificates_valid_to', 'certificates', ['valid_to'], unique=False)

    # 13. subdomain_certificates association table
    op.create_table(
        'subdomain_certificates',
        sa.Column('subdomain_id', sa.Uuid(), nullable=False),
        sa.Column('certificate_id', sa.Uuid(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subdomain_id', 'certificate_id'),
    )

    # 14. technologies table
    op.create_table(
        'technologies',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('service_id', sa.Uuid(), nullable=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=True),
        sa.Column('cpe', sa.String(length=255), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.8'),
        sa.Column('evidence_source', sa.String(length=100), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['service_exposures.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_technologies_asset_id', 'technologies', ['asset_id'], unique=False)
    op.create_index('ix_technologies_name', 'technologies', ['name'], unique=False)
    op.create_index('ix_technologies_service_id', 'technologies', ['service_id'], unique=False)

    # 15. vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_v3_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=100), nullable=True),
        sa.Column('affected_cpe_patterns', sa.JSON(), nullable=False),
        sa.Column('published_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False, server_default='NVD'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'], unique=True)
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'], unique=False)

    # 16. technology_vulnerabilities table
    op.create_table(
        'technology_vulnerabilities',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('technology_id', sa.Uuid(), nullable=False),
        sa.Column('vulnerability_id', sa.Uuid(), nullable=False),
        sa.Column('match_confidence', sa.Float(), nullable=False, server_default='0.7'),
        sa.Column('verification_status', sa.String(length=50), nullable=False, server_default='requires_verification'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['technology_id'], ['technologies.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('technology_id', 'vulnerability_id', name='uq_technology_vulnerability'),
    )
    op.create_index('ix_technology_vulnerabilities_technology_id', 'technology_vulnerabilities', ['technology_id'], unique=False)
    op.create_index('ix_technology_vulnerabilities_verification_status', 'technology_vulnerabilities', ['verification_status'], unique=False)
    op.create_index('ix_technology_vulnerabilities_vulnerability_id', 'technology_vulnerabilities', ['vulnerability_id'], unique=False)

    # 17. findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('reference_code', sa.String(length=50), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('context_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('score_breakdown', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='open'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_findings_asset_id', 'findings', ['asset_id'], unique=False)
    op.create_index('ix_findings_category', 'findings', ['category'], unique=False)
    op.create_index('ix_findings_context_score', 'findings', ['context_score'], unique=False)
    op.create_index('ix_findings_investigation_id', 'findings', ['investigation_id'], unique=False)
    op.create_index('ix_findings_reference_code', 'findings', ['reference_code'], unique=True)
    op.create_index('ix_findings_severity', 'findings', ['severity'], unique=False)
    op.create_index('ix_findings_status', 'findings', ['status'], unique=False)

    # 18. evidence table
    op.create_table(
        'evidence',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('reference_code', sa.String(length=50), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=True),
        sa.Column('finding_id', sa.Uuid(), nullable=True),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('raw_payload', sa.Text(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('verified_integrity', sa.Boolean(), nullable=False, server_default='true'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_evidence_asset_id', 'evidence', ['asset_id'], unique=False)
    op.create_index('ix_evidence_evidence_type', 'evidence', ['evidence_type'], unique=False)
    op.create_index('ix_evidence_finding_id', 'evidence', ['finding_id'], unique=False)
    op.create_index('ix_evidence_investigation_id', 'evidence', ['investigation_id'], unique=False)
    op.create_index('ix_evidence_reference_code', 'evidence', ['reference_code'], unique=True)
    op.create_index('ix_evidence_sha256_hash', 'evidence', ['sha256_hash'], unique=False)

    # 19. asset_relationships table
    op.create_table(
        'asset_relationships',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('source_asset_id', sa.Uuid(), nullable=False),
        sa.Column('target_asset_id', sa.Uuid(), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('attributes', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id', 'source_asset_id', 'target_asset_id', 'relationship_type', name='uq_investigation_asset_relationship'),
    )
    op.create_index('ix_asset_relationships_investigation_id', 'asset_relationships', ['investigation_id'], unique=False)
    op.create_index('ix_asset_relationships_relationship_type', 'asset_relationships', ['relationship_type'], unique=False)
    op.create_index('ix_asset_relationships_source_asset_id', 'asset_relationships', ['source_asset_id'], unique=False)
    op.create_index('ix_asset_relationships_target_asset_id', 'asset_relationships', ['target_asset_id'], unique=False)

    # 20. change_records table
    op.create_table(
        'change_records',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('previous_scan_id', sa.Uuid(), nullable=True),
        sa.Column('current_scan_id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=False),
        sa.Column('change_type', sa.String(length=20), nullable=False),
        sa.Column('field_name', sa.String(length=100), nullable=False),
        sa.Column('old_value', sa.JSON(), nullable=True),
        sa.Column('new_value', sa.JSON(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['current_scan_id'], ['scan_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['previous_scan_id'], ['scan_runs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_change_records_asset_id', 'change_records', ['asset_id'], unique=False)
    op.create_index('ix_change_records_change_type', 'change_records', ['change_type'], unique=False)
    op.create_index('ix_change_records_current_scan_id', 'change_records', ['current_scan_id'], unique=False)
    op.create_index('ix_change_records_investigation_id', 'change_records', ['investigation_id'], unique=False)
    op.create_index('ix_change_records_previous_scan_id', 'change_records', ['previous_scan_id'], unique=False)

    # 21. timeline_events table
    op.create_table(
        'timeline_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('asset_id', sa.Uuid(), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_timeline_events_asset_id', 'timeline_events', ['asset_id'], unique=False)
    op.create_index('ix_timeline_events_event_time', 'timeline_events', ['event_time'], unique=False)
    op.create_index('ix_timeline_events_event_type', 'timeline_events', ['event_type'], unique=False)
    op.create_index('ix_timeline_events_investigation_id', 'timeline_events', ['investigation_id'], unique=False)


def downgrade() -> None:
    op.drop_table('timeline_events')
    op.drop_table('change_records')
    op.drop_table('asset_relationships')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('technology_vulnerabilities')
    op.drop_table('vulnerabilities')
    op.drop_table('technologies')
    op.drop_table('subdomain_certificates')
    op.drop_table('certificates')
    op.drop_table('service_exposures')
    op.drop_table('ip_addresses')
    op.drop_table('asns')
    op.drop_table('dns_records')
    op.drop_table('subdomains')
    op.drop_table('domains')
    op.drop_table('assets')
    op.drop_table('scan_runs')
    op.drop_table('investigations')
    op.drop_table('targets')
    op.drop_table('users')
