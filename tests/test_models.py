"""Unit and integration tests for Stage 1 SQLAlchemy domain models and constraints."""

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database.base import Base
from backend.app.models import (
    User,
    Target,
    Investigation,
    ScanRun,
    Asset,
    Domain,
    Subdomain,
    DNSRecord,
    ASN,
    IPAddress,
    ServiceExposure,
    Certificate,
    Technology,
    TechnologyVulnerability,
    Vulnerability,
    Finding,
    Evidence,
    AssetRelationship,
    ChangeRecord,
    TimelineEvent,
)


@pytest.fixture(scope="module")
def db_session():
    """In-memory SQLite database session fixture for isolated schema and model testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def test_metadata_contains_all_tables():
    """Verify that all 18 Stage 1 domain tables are registered in Base.metadata."""
    expected_tables = {
        "users",
        "targets",
        "investigations",
        "scan_runs",
        "assets",
        "domains",
        "subdomains",
        "dns_records",
        "asns",
        "ip_addresses",
        "service_exposures",
        "certificates",
        "subdomain_certificates",
        "technologies",
        "vulnerabilities",
        "technology_vulnerabilities",
        "findings",
        "evidence",
        "asset_relationships",
        "change_records",
        "timeline_events",
    }
    registered_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(registered_tables)


def test_target_and_investigation_hierarchy(db_session):
    """Verify Target -> Investigation -> ScanRun relationships and cascading."""
    target = Target(
        name="Example Corp",
        primary_domain="example.com",
        organization="Example Inc.",
        is_authorized=True,
    )
    db_session.add(target)
    db_session.commit()

    investigation = Investigation(
        reference_code="INV-2026-0001",
        target_id=target.id,
        title="Initial Surface Assessment",
        status="pending",
        scan_options={"ct_enabled": True, "dns_enabled": True},
    )
    db_session.add(investigation)
    db_session.commit()

    scan_run = ScanRun(
        investigation_id=investigation.id,
        run_number=1,
        status="completed",
        total_discovered_assets=5,
        total_resolving_assets=3,
        summary={"subdomains": 5, "ips": 2},
    )
    db_session.add(scan_run)
    db_session.commit()

    # Query back and assert relationships
    retrieved_target = db_session.get(Target, target.id)
    assert len(retrieved_target.investigations) == 1
    assert retrieved_target.investigations[0].reference_code == "INV-2026-0001"
    assert len(retrieved_target.investigations[0].scan_runs) == 1
    assert retrieved_target.investigations[0].scan_runs[0].total_discovered_assets == 5


def test_asset_hierarchy_and_subdomain_resolution(db_session):
    """Verify Asset -> Domain -> Subdomain -> DNS Record structure."""
    target = db_session.query(Target).filter_by(primary_domain="example.com").first()
    investigation = target.investigations[0]

    # Create root domain asset
    domain_asset = Asset(
        target_id=target.id,
        investigation_id=investigation.id,
        asset_type="domain",
        value="example.com",
        is_active=True,
        source="rdap",
    )
    db_session.add(domain_asset)
    db_session.commit()

    domain = Domain(
        asset_id=domain_asset.id,
        domain_name="example.com",
        registrar="MarkMonitor Inc.",
        nameservers=["ns1.example.com", "ns2.example.com"],
        status=["clientTransferProhibited"],
    )
    db_session.add(domain)
    db_session.commit()

    # Create subdomain asset (resolving active)
    subdomain_asset = Asset(
        target_id=target.id,
        investigation_id=investigation.id,
        asset_type="subdomain",
        value="api.example.com",
        is_active=True,
        source="crt.sh",
    )
    db_session.add(subdomain_asset)
    db_session.commit()

    subdomain = Subdomain(
        asset_id=subdomain_asset.id,
        domain_id=domain.id,
        subdomain_name="api.example.com",
        is_resolving=True,
        discovery_source="crt.sh",
    )
    db_session.add(subdomain)
    db_session.commit()

    # Add DNS A record
    dns_rec = DNSRecord(
        subdomain_id=subdomain.id,
        record_type="A",
        value="203.0.113.10",
        ttl=300,
        resolver="8.8.8.8",
    )
    db_session.add(dns_rec)
    db_session.commit()

    # Assertions
    retrieved_subdomain = db_session.get(Subdomain, subdomain.id)
    assert retrieved_subdomain.is_resolving is True
    assert len(retrieved_subdomain.dns_records) == 1
    assert retrieved_subdomain.dns_records[0].value == "203.0.113.10"
    assert retrieved_subdomain.domain.domain_name == "example.com"


def test_technology_and_cve_correlation(db_session):
    """
    Verify Technology -> Vulnerability correlation adheres to the project principle:
    distinguish Observed technology from Potential CVE requiring verification.
    """
    target = db_session.query(Target).filter_by(primary_domain="example.com").first()
    investigation = target.investigations[0]

    asset = Asset(
        target_id=target.id,
        investigation_id=investigation.id,
        asset_type="subdomain",
        value="portal.example.com",
        is_active=True,
        source="http_probe",
    )
    db_session.add(asset)
    db_session.commit()

    tech = Technology(
        asset_id=asset.id,
        name="Apache HTTP Server",
        version="2.4.49",
        category="web_server",
        confidence=0.95,
        evidence_source="Server HTTP header",
    )
    db_session.add(tech)

    vuln = Vulnerability(
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal",
        description="Path traversal and file disclosure in Apache HTTP Server 2.4.49",
        severity="CRITICAL",
        cvss_v3_score=9.8,
        affected_cpe_patterns=["cpe:2.3:a:apache:http_server:2.4.49:*"],
    )
    db_session.add(vuln)
    db_session.commit()

    # Link through correlation association
    tech_vuln = TechnologyVulnerability(
        technology_id=tech.id,
        vulnerability_id=vuln.id,
        match_confidence=0.90,
        verification_status="requires_verification",
        notes="Version matches vulnerable range; requires authorized validation.",
    )
    db_session.add(tech_vuln)
    db_session.commit()

    # Assertions
    retrieved_tech = db_session.get(Technology, tech.id)
    assert len(retrieved_tech.vulnerability_correlations) == 1
    correlation = retrieved_tech.vulnerability_correlations[0]
    assert correlation.verification_status == "requires_verification"
    assert correlation.vulnerability.cve_id == "CVE-2021-41773"


def test_cryptographic_evidence_integrity(db_session):
    """Verify SHA-256 evidence computation and integrity verification method."""
    target = db_session.query(Target).filter_by(primary_domain="example.com").first()
    investigation = target.investigations[0]

    raw_ct_data = '{"issuer": "Let\'s Encrypt", "not_after": "2026-12-01", "san": ["api.example.com"]}'
    computed_hash = Evidence.compute_sha256(raw_ct_data)

    evidence = Evidence(
        reference_code="EV-00001",
        investigation_id=investigation.id,
        evidence_type="ct_log",
        source="crt.sh",
        raw_payload=raw_ct_data,
        sha256_hash=computed_hash,
        verified_integrity=True,
    )
    db_session.add(evidence)
    db_session.commit()

    retrieved = db_session.get(Evidence, evidence.id)
    assert retrieved.verify_hash() is True

    # Tamper test
    retrieved.raw_payload = '{"tampered": true}'
    assert retrieved.verify_hash() is False


def test_asset_relationship_graph_edge(db_session):
    """Verify graph relationship edge creation for attack surface correlation."""
    target = db_session.query(Target).filter_by(primary_domain="example.com").first()
    investigation = target.investigations[0]

    domain_asset = db_session.query(Asset).filter_by(value="example.com").first()
    subdomain_asset = (
        db_session.query(Asset).filter_by(value="api.example.com").first()
    )

    edge = AssetRelationship(
        investigation_id=investigation.id,
        source_asset_id=domain_asset.id,
        target_asset_id=subdomain_asset.id,
        relationship_type="has_subdomain",
        confidence=1.0,
        attributes={"discovery": "crt.sh"},
    )
    db_session.add(edge)
    db_session.commit()

    retrieved_edge = db_session.get(AssetRelationship, edge.id)
    assert retrieved_edge.relationship_type == "has_subdomain"
    assert retrieved_edge.source_asset.value == "example.com"
    assert retrieved_edge.target_asset.value == "api.example.com"


def test_scan_run_observation_tracking_and_history(db_session):
    """
    Verify that individual ScanRuns track their distinct observations,
    allowing complete point-in-time snapshot reconstruction for the same asset.
    """
    target = Target(
        name="Snapshot Corp",
        primary_domain="snapshot.example",
        organization="Snapshot Inc.",
        is_authorized=True,
    )
    db_session.add(target)
    db_session.commit()

    investigation = Investigation(
        reference_code="INV-2026-0002",
        target_id=target.id,
        title="Multi-Scan Historical Audit",
        status="running",
    )
    db_session.add(investigation)
    db_session.commit()

    # Canonical Subdomain Asset
    subdomain_asset = Asset(
        target_id=target.id,
        investigation_id=investigation.id,
        asset_type="subdomain",
        value="api.snapshot.example",
        is_active=True,
        source="crt.sh",
    )
    db_session.add(subdomain_asset)
    db_session.commit()

    root_domain = Domain(
        asset_id=subdomain_asset.id,
        domain_name="snapshot.example",
    )
    # We create a specific subdomain record
    subdomain_record = Subdomain(
        asset_id=subdomain_asset.id,
        domain_id=target.investigations[0].assets[0].domain.id if target.investigations[0].assets[0].domain else None or db_session.query(Domain).first().id,
        subdomain_name="api.snapshot.example",
        is_resolving=True,
        discovery_source="crt.sh",
    )
    db_session.add(subdomain_record)
    db_session.commit()

    # --- ScanRun #1 ---
    scan_1 = ScanRun(
        investigation_id=investigation.id,
        run_number=1,
        status="completed",
        total_discovered_assets=1,
        total_resolving_assets=1,
    )
    db_session.add(scan_1)
    db_session.commit()

    # Observations for ScanRun #1
    dns_1 = DNSRecord(
        subdomain_id=subdomain_record.id,
        scan_run_id=scan_1.id,
        record_type="A",
        value="1.2.3.4",
        resolver="8.8.8.8",
    )
    service_1 = ServiceExposure(
        asset_id=subdomain_asset.id,
        scan_run_id=scan_1.id,
        port=443,
        protocol="tcp",
        service_name="https",
        tls_version="TLSv1.2",
    )
    db_session.add_all([dns_1, service_1])
    db_session.commit()

    tech_1 = Technology(
        asset_id=subdomain_asset.id,
        service_id=service_1.id,
        scan_run_id=scan_1.id,
        name="nginx",
        version="1.18.0",
        category="web_server",
        confidence=0.9,
        evidence_source="Server header",
    )
    evidence_1 = Evidence(
        reference_code="EV-00101",
        investigation_id=investigation.id,
        asset_id=subdomain_asset.id,
        scan_run_id=scan_1.id,
        evidence_type="http_headers",
        source="HTTP Response",
        raw_payload="Server: nginx/1.18.0",
        sha256_hash=Evidence.compute_sha256("Server: nginx/1.18.0"),
    )
    subdomain_asset.last_scan_run_id = scan_1.id
    db_session.add_all([tech_1, evidence_1])
    db_session.commit()

    # --- ScanRun #2 (Infrastructure Changed) ---
    scan_2 = ScanRun(
        investigation_id=investigation.id,
        run_number=2,
        status="completed",
        total_discovered_assets=1,
        total_resolving_assets=1,
    )
    db_session.add(scan_2)
    db_session.commit()

    # Observations for ScanRun #2
    dns_2 = DNSRecord(
        subdomain_id=subdomain_record.id,
        scan_run_id=scan_2.id,
        record_type="A",
        value="1.2.3.5",
        resolver="8.8.8.8",
    )
    service_2 = ServiceExposure(
        asset_id=subdomain_asset.id,
        scan_run_id=scan_2.id,
        port=443,
        protocol="tcp",
        service_name="https",
        tls_version="TLSv1.3",
    )
    db_session.add_all([dns_2, service_2])
    db_session.commit()

    tech_2 = Technology(
        asset_id=subdomain_asset.id,
        service_id=service_2.id,
        scan_run_id=scan_2.id,
        name="nginx",
        version="1.24.0",
        category="web_server",
        confidence=0.95,
        evidence_source="Server header",
    )
    evidence_2 = Evidence(
        reference_code="EV-00102",
        investigation_id=investigation.id,
        asset_id=subdomain_asset.id,
        scan_run_id=scan_2.id,
        evidence_type="http_headers",
        source="HTTP Response",
        raw_payload="Server: nginx/1.24.0",
        sha256_hash=Evidence.compute_sha256("Server: nginx/1.24.0"),
    )
    subdomain_asset.last_scan_run_id = scan_2.id
    db_session.add_all([tech_2, evidence_2])
    db_session.commit()

    # --- Verify Snapshot Reconstruction ---
    # ScanRun #1 Snapshot Query
    scan1_dns = db_session.query(DNSRecord).filter_by(scan_run_id=scan_1.id).all()
    scan1_tech = db_session.query(Technology).filter_by(scan_run_id=scan_1.id).all()
    scan1_evidence = db_session.query(Evidence).filter_by(scan_run_id=scan_1.id).all()

    assert len(scan1_dns) == 1
    assert scan1_dns[0].value == "1.2.3.4"
    assert len(scan1_tech) == 1
    assert scan1_tech[0].version == "1.18.0"
    assert len(scan1_evidence) == 1
    assert "1.18.0" in scan1_evidence[0].raw_payload

    # ScanRun #2 Snapshot Query
    scan2_dns = db_session.query(DNSRecord).filter_by(scan_run_id=scan_2.id).all()
    scan2_tech = db_session.query(Technology).filter_by(scan_run_id=scan_2.id).all()
    scan2_evidence = db_session.query(Evidence).filter_by(scan_run_id=scan_2.id).all()

    assert len(scan2_dns) == 1
    assert scan2_dns[0].value == "1.2.3.5"
    assert len(scan2_tech) == 1
    assert scan2_tech[0].version == "1.24.0"
    assert len(scan2_evidence) == 1
    assert "1.24.0" in scan2_evidence[0].raw_payload

    # Verify Asset last_scan_run linkage
    retrieved_asset = db_session.get(Asset, subdomain_asset.id)
    assert retrieved_asset.last_scan_run_id == scan_2.id
    assert retrieved_asset.last_scan_run.run_number == 2

    # Verify ScanRun reverse relationships
    retrieved_scan1 = db_session.get(ScanRun, scan_1.id)
    assert len(retrieved_scan1.dns_records) == 1
    assert retrieved_scan1.dns_records[0].value == "1.2.3.4"
    assert len(retrieved_scan1.technologies) == 1
    assert retrieved_scan1.technologies[0].version == "1.18.0"

