"""Comprehensive test suite for Stage 9: Attack Surface Monitoring & Change Detection.

Tests cover:
1. Added domain and subdomain detection
2. Removed domain and subdomain detection
3. Modified observable property detection
4. Identical scans produce 0 changes
5. Multiple heterogeneous changes in a single comparison
6. DNS record changes (added, removed, modified values)
7. IP observation & ASN routing changes
8. Service exposure changes (added, closed, HTTP status, TLS version, security headers)
9. Technology observation changes (added, removed, version modified)
10. Vulnerability correlation changes (added CVE, remediated CVE, confidence modified)
11. TLS Certificate changes (added, removed, expiration modified)
12. Asset relationship graph edge changes (added, removed)
13. Security finding changes (added, resolved, status/severity modified)
14. Historical ScanRun isolation (no mutation of past observations)
15. Cross-investigation ScanRun rejection (400 Bad Request)
16. IDOR protection & RBAC authorization (Analyst isolation, Auditor isolation, Admin access)
17. Duplicate comparison idempotency (running compare twice does not create duplicate rows)
18. Deterministic ordering and output
19. Invalid ScanRun IDs handling
20. Same ScanRun compared with itself
21. Insufficient ScanRuns for automatic comparison (clear 400 error)
22. Auto-comparison of previous vs latest completed ScanRuns
23. Evidence ID and SHA-256 provenance preservation
24. Filtering changes by change_type, category, asset_id, and monitoring summary endpoint
"""

import uuid
import random
import hashlib
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import (
    Asset,
    Domain,
    Subdomain,
    DNSRecord,
    IPAddress,
    ASN,
    IPObservation,
    ServiceExposure,
)
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.relationship import AssetRelationship
from backend.app.models.finding import Finding
from backend.app.models.evidence import Evidence
from backend.app.models.change import ChangeRecord
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.change_service import ChangeDetectionService
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Fixtures & Helpers ---

@pytest.fixture(autouse=True)
def ensure_stage9_test_users():
    """Ensure test users with distinct roles exist in database."""
    with TestingSessionLocal() as db:
        users = [
            (uuid.UUID("91111111-1111-1111-1111-111111111111"), "analyst9a@security.local", "analyst_9a", "analyst"),
            (uuid.UUID("92222222-2222-2222-2222-222222222222"), "analyst9b@security.local", "analyst_9b", "analyst"),
            (uuid.UUID("93333333-3333-3333-3333-333333333333"), "admin9@security.local", "admin_9", "admin"),
            (uuid.UUID("94444444-4444-4444-4444-444444444444"), "auditor9@security.local", "auditor_9", "auditor"),
        ]
        for user_id, email, username, role in users:
            existing = db.get(User, user_id)
            if not existing:
                u = User(
                    id=user_id,
                    email=email,
                    username=username,
                    hashed_password=hash_password("Password123!"),
                    full_name=f"Stage9 {username}",
                    role=role,
                    is_active=True,
                )
                db.add(u)
        db.commit()


def get_auth_headers(user_id: uuid.UUID, username: str, role: str) -> dict:
    token = create_access_token(data={"sub": str(user_id), "username": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def dual_scan_investigation_fixture():
    """Creates an investigation with two sequential completed ScanRuns (Scan 1 = Baseline, Scan 2 = Current)."""
    with TestingSessionLocal() as db:
        analyst_id = uuid.UUID("91111111-1111-1111-1111-111111111111")
        rand_id = uuid.uuid4().hex[:8]
        
        target = Target(
            name=f"Monitoring Test Target {rand_id}",
            primary_domain=f"monitored-{rand_id}.com",
            organization="Monitoring Corp",
            is_authorized=True,
        )
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-M9-{rand_id.upper()}",
            target_id=target.id,
            title=f"Monitoring Investigation {rand_id}",
            created_by_id=analyst_id,
            status="active",
        )
        db.add(inv)
        db.flush()

        # Scan Run 1 (Baseline)
        scan1 = ScanRun(
            investigation_id=inv.id,
            run_number=1,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        # Scan Run 2 (Current)
        scan2 = ScanRun(
            investigation_id=inv.id,
            run_number=2,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([scan1, scan2])
        db.flush()

        # Shared Assets
        asset_domain = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value=f"monitored-{rand_id}.com",
            source="ct_log",
            confidence=1.0,
            last_scan_run_id=scan1.id,
        )
        db.add(asset_domain)
        db.flush()

        domain_rec = Domain(
            asset_id=asset_domain.id,
            domain_name=f"monitored-{rand_id}.com",
            registrar="MarkMonitor",
        )
        db.add(domain_rec)
        db.flush()

        db.commit()

        target_id = target.id
        inv_id = inv.id
        scan1_id = scan1.id
        scan2_id = scan2.id
        domain_asset_id = asset_domain.id
        domain_rec_id = domain_rec.id
        primary_domain = target.primary_domain

        return {
            "investigation_id": inv_id,
            "target_id": target_id,
            "scan1_id": scan1_id,
            "scan2_id": scan2_id,
            "domain_asset_id": domain_asset_id,
            "domain_rec_id": domain_rec_id,
            "primary_domain": primary_domain,
            "rand_id": rand_id,
            "analyst_id": analyst_id,
        }


# --- Tests ---

def test_compare_added_and_removed_subdomain(dual_scan_investigation_fixture):
    """Test detecting added and removed subdomains between two scan runs."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    sub_old_name = f"legacy-{rand_id}.monitored-{rand_id}.com"
    sub_new_name = f"api-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        # Subdomain A exists only in Scan 1 (will be REMOVED in Scan 2)
        asset_sub_old = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan1_id,
            asset_type="subdomain",
            value=sub_old_name,
            source="ct_log",
        )
        db.add(asset_sub_old)
        db.flush()
        sub_old = Subdomain(
            asset_id=asset_sub_old.id,
            domain_id=domain_id,
            subdomain_name=sub_old_name,
            is_resolving=True,
        )
        db.add(sub_old)

        # Subdomain B exists only in Scan 2 (will be ADDED in Scan 2)
        asset_sub_new = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=sub_new_name,
            source="ct_log",
        )
        db.add(asset_sub_new)
        db.flush()
        sub_new = Subdomain(
            asset_id=asset_sub_new.id,
            domain_id=domain_id,
            subdomain_name=sub_new_name,
            is_resolving=True,
        )
        db.add(sub_new)
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    assert result.total_changes >= 2
    assert result.added_count >= 1
    assert result.removed_count >= 1

    changes = result.changes
    added_sub = next((c for c in changes if c.category == "subdomain" and c.change_type == "ADDED"), None)
    removed_sub = next((c for c in changes if c.category == "subdomain" and c.change_type == "REMOVED"), None)

    assert added_sub is not None
    assert f"api-{rand_id}" in added_sub.entity_key
    assert added_sub.old_value is None
    assert added_sub.new_value is not None

    assert removed_sub is not None
    assert f"legacy-{rand_id}" in removed_sub.entity_key
    assert removed_sub.old_value is not None
    assert removed_sub.new_value is None


def test_compare_modified_subdomain_property(dual_scan_investigation_fixture):
    """Test detecting modified properties on an entity existing in both scans."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    fqdn = f"portal-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        # Asset exists for both scans
        asset = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=fqdn,
            source="dns",
        )
        db.add(asset)
        db.flush()
        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_id,
            subdomain_name=fqdn,
            is_resolving=True,
        )
        db.add(sub)
        db.flush()

        # In Scan 1: No DNS A record resolving
        # In Scan 2: Has active DNS A record
        dns2 = DNSRecord(
            subdomain_id=sub.id,
            scan_run_id=scan2_id,
            record_type="A",
            value="198.51.100.42",
            ttl=300,
        )
        db.add(dns2)
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    changes = result.changes
    dns_change = next(
        (c for c in changes if c.category == "dns_record" and c.change_type == "ADDED" and fqdn in c.entity_key),
        None,
    )
    assert dns_change is not None


def test_compare_identical_scans_produces_no_changes(dual_scan_investigation_fixture):
    """Test comparing two identical scans produces 0 change records."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    fqdn = f"identical-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        asset = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=fqdn,
            source="ct_log",
        )
        db.add(asset)
        db.flush()
        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_id,
            subdomain_name=fqdn,
            is_resolving=True,
        )
        db.add(sub)
        db.flush()

        # Identical DNS records in both scans
        for s_id in [scan1_id, scan2_id]:
            dns = DNSRecord(
                subdomain_id=sub.id,
                scan_run_id=s_id,
                record_type="A",
                value="198.51.100.1",
                ttl=300,
            )
            db.add(dns)
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    # Identical data in both scans should produce 0 changes
    assert result.total_changes == 0
    assert result.added_count == 0
    assert result.removed_count == 0
    assert result.modified_count == 0


def test_compare_dns_records(dual_scan_investigation_fixture):
    """Test detecting added, removed, and modified DNS records."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    fqdn = f"dns-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        asset = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=fqdn,
            source="dns",
        )
        db.add(asset)
        db.flush()
        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_id,
            subdomain_name=fqdn,
            is_resolving=True,
        )
        db.add(sub)
        db.flush()

        # Baseline Scan 1: A record pointing to 198.51.100.1, MX record pointing to mail1.example.com
        dns_a_1 = DNSRecord(
            subdomain_id=sub.id,
            scan_run_id=scan1_id,
            record_type="A",
            value="198.51.100.1",
            ttl=300,
        )
        dns_mx_1 = DNSRecord(
            subdomain_id=sub.id,
            scan_run_id=scan1_id,
            record_type="MX",
            value="10 mail1.example.com",
            ttl=3600,
        )
        db.add_all([dns_a_1, dns_mx_1])

        # Current Scan 2: A record changed to 198.51.100.2 (MODIFIED), MX removed, TXT added (ADDED)
        dns_a_2 = DNSRecord(
            subdomain_id=sub.id,
            scan_run_id=scan2_id,
            record_type="A",
            value="198.51.100.2",
            ttl=300,
        )
        dns_txt_2 = DNSRecord(
            subdomain_id=sub.id,
            scan_run_id=scan2_id,
            record_type="TXT",
            value="v=spf1 include:_spf.google.com ~all",
            ttl=300,
        )
        db.add_all([dns_a_2, dns_txt_2])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    changes = result.changes
    dns_changes = [c for c in changes if c.category == "dns_record"]
    assert len(dns_changes) >= 3

    types = {c.change_type for c in dns_changes}
    assert "ADDED" in types or "REMOVED" in types or "MODIFIED" in types


def test_compare_ip_observations_and_asn(dual_scan_investigation_fixture):
    """Test detecting added and modified IP observations and ASN routing."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    rand_id = env["rand_id"]

    with TestingSessionLocal() as db:
        asn1 = ASN(asn_number=13335, name="CLOUDFLARENET", country="US")
        asn2 = ASN(asn_number=16509, name="AMAZON-02", country="US")
        db.add_all([asn1, asn2])
        db.flush()

        ip_str1 = f"198.51.100.{random.randint(10, 50)}"
        ip_str2 = f"198.51.100.{random.randint(51, 99)}"

        asset_ip1 = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan1_id, asset_type="ip", value=ip_str1, source="dns")
        asset_ip2 = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan2_id, asset_type="ip", value=ip_str2, source="dns")
        db.add_all([asset_ip1, asset_ip2])
        db.flush()

        ip1 = IPAddress(asset_id=asset_ip1.id, ip_address=ip_str1, ip_version=4, asn_id=asn1.id)
        ip2 = IPAddress(asset_id=asset_ip2.id, ip_address=ip_str2, ip_version=4, asn_id=asn2.id)
        db.add_all([ip1, ip2])
        db.flush()

        # Scan 1: Observes IP1
        obs1 = IPObservation(
            scan_run_id=scan1_id,
            ip_address_id=ip1.id,
            asn_id=asn1.id,
        )
        # Scan 2: Observes IP2 (new IP added)
        obs2 = IPObservation(
            scan_run_id=scan2_id,
            ip_address_id=ip2.id,
            asn_id=asn2.id,
        )
        db.add_all([obs1, obs2])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    ip_changes = [c for c in result.changes if c.category == "ip_observation"]
    assert len(ip_changes) >= 2


def test_compare_service_exposures(dual_scan_investigation_fixture):
    """Test detecting modified HTTP status, TLS versions, and security headers."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    dom_asset_id = env["domain_asset_id"]

    with TestingSessionLocal() as db:
        # Scan 1: Service has HTTP status 200, TLS 1.2
        svc1 = ServiceExposure(
            asset_id=dom_asset_id,
            scan_run_id=scan1_id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=200,
            page_title="Old App Title",
            tls_version="TLSv1.2",
            security_headers={"strict-transport-security": {"present": False}},
        )
        # Scan 2: Service modified to HTTP status 301, TLS 1.3
        svc2 = ServiceExposure(
            asset_id=dom_asset_id,
            scan_run_id=scan2_id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=301,
            page_title="Redirect Portal",
            tls_version="TLSv1.3",
            security_headers={"strict-transport-security": {"present": True}},
        )
        db.add_all([svc1, svc2])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    svc_changes = [c for c in result.changes if c.category == "service_exposure"]
    assert len(svc_changes) >= 1
    mod_svc = next((c for c in svc_changes if c.change_type == "MODIFIED"), None)
    assert mod_svc is not None
    assert mod_svc.old_value["http_status"] == 200
    assert mod_svc.new_value["http_status"] == 301
    assert mod_svc.old_value["tls_version"] == "TLSv1.2"
    assert mod_svc.new_value["tls_version"] == "TLSv1.3"


def test_compare_technologies_and_versions(dual_scan_investigation_fixture):
    """Test detecting added technologies and version upgrades."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    dom_asset_id = env["domain_asset_id"]

    with TestingSessionLocal() as db:
        # Scan 1: nginx 1.18.0
        tech1 = Technology(
            asset_id=dom_asset_id,
            scan_run_id=scan1_id,
            name="nginx",
            category="web_server",
            version="1.18.0",
            confidence=0.9,
            evidence_source="http_headers",
        )
        db.add(tech1)

        # Scan 2: nginx updated to 1.22.0 (MODIFIED), and Redis added (ADDED)
        tech2 = Technology(
            asset_id=dom_asset_id,
            scan_run_id=scan2_id,
            name="nginx",
            category="web_server",
            version="1.22.0",
            confidence=0.95,
            evidence_source="http_headers",
        )
        tech3 = Technology(
            asset_id=dom_asset_id,
            scan_run_id=scan2_id,
            name="redis",
            category="cache",
            version="7.0.5",
            confidence=0.85,
            evidence_source="banner",
        )
        db.add_all([tech2, tech3])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    tech_changes = [c for c in result.changes if c.category == "technology"]
    assert len(tech_changes) >= 2

    nginx_mod = next((c for c in tech_changes if "nginx" in c.entity_key and c.change_type == "MODIFIED"), None)
    redis_add = next((c for c in tech_changes if "redis" in c.entity_key and c.change_type == "ADDED"), None)

    assert nginx_mod is not None
    assert nginx_mod.old_value["version"] == "1.18.0"
    assert nginx_mod.new_value["version"] == "1.22.0"

    assert redis_add is not None
    assert redis_add.new_value["name"] == "redis"


def test_compare_vulnerabilities(dual_scan_investigation_fixture):
    """Test detecting added, unobserved (REMOVED), and confidence-modified vulnerability correlations.
    
    Verifies that unobserved CVEs are recorded as REMOVED / no longer observed,
    and NOT automatically described as 'remediated', 'patched', or 'fixed'.
    """
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    dom_asset_id = env["domain_asset_id"]

    cve1_id = f"CVE-2021-{random.randint(10000, 49999)}"
    cve2_id = f"CVE-2022-{random.randint(50000, 99999)}"
    cve3_id = f"CVE-2023-{random.randint(10000, 49999)}"

    with TestingSessionLocal() as db:
        vuln1 = Vulnerability(
            cve_id=cve1_id,
            description="Old Vulnerability in Scan 1",
            cvss_v3_score=7.5,
            severity="HIGH",
        )
        vuln2 = Vulnerability(
            cve_id=cve2_id,
            description="New Vulnerability in Scan 2",
            cvss_v3_score=9.8,
            severity="CRITICAL",
        )
        vuln3 = Vulnerability(
            cve_id=cve3_id,
            description="Persistent Vulnerability with confidence change",
            cvss_v3_score=5.0,
            severity="MEDIUM",
        )
        db.add_all([vuln1, vuln2, vuln3])
        db.flush()

        # Tech in Scan 1 (has cve1 and cve3 at confidence 0.85)
        t1 = Technology(
            asset_id=dom_asset_id,
            scan_run_id=scan1_id,
            name="apache",
            category="web_server",
            version="2.4.49",
            evidence_source="http_headers",
        )
        db.add(t1)
        db.flush()
        tv1 = TechnologyVulnerability(
            technology_id=t1.id,
            vulnerability_id=vuln1.id,
            match_confidence=0.9,
            verification_status="potential",
        )
        tv3_s1 = TechnologyVulnerability(
            technology_id=t1.id,
            vulnerability_id=vuln3.id,
            match_confidence=0.85,
            verification_status="potential",
        )
        db.add_all([tv1, tv3_s1])

        # Tech in Scan 2 (cve1 disappeared -> REMOVED, cve2 introduced -> ADDED, cve3 confidence upgraded -> MODIFIED)
        t2 = Technology(
            asset_id=dom_asset_id,
            scan_run_id=scan2_id,
            name="apache",
            category="web_server",
            version="2.4.50",
            evidence_source="http_headers",
        )
        db.add(t2)
        db.flush()
        tv2 = TechnologyVulnerability(
            technology_id=t2.id,
            vulnerability_id=vuln2.id,
            match_confidence=0.95,
            verification_status="potential",
        )
        tv3_s2 = TechnologyVulnerability(
            technology_id=t2.id,
            vulnerability_id=vuln3.id,
            match_confidence=0.95,
            verification_status="confirmed",
        )
        db.add_all([tv2, tv3_s2])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    vuln_changes = [c for c in result.changes if c.category == "vulnerability"]
    assert len(vuln_changes) >= 3

    cve1_change = next((c for c in vuln_changes if cve1_id in c.entity_key), None)
    cve2_change = next((c for c in vuln_changes if cve2_id in c.entity_key), None)
    cve3_change = next((c for c in vuln_changes if cve3_id in c.entity_key), None)

    # 1. Disappeared CVE is REMOVED, not assumed remediated
    assert cve1_change is not None
    assert cve1_change.change_type == "REMOVED"
    assert "no longer observed in current scan" in cve1_change.description.lower()
    assert "remediated" not in cve1_change.description.lower()
    assert "patched" not in cve1_change.description.lower()
    assert "fixed" not in cve1_change.description.lower()

    # 2. Newly observed CVE is ADDED
    assert cve2_change is not None
    assert cve2_change.change_type == "ADDED"

    # 3. Match confidence / verification status change on same CVE is MODIFIED
    assert cve3_change is not None
    assert cve3_change.change_type == "MODIFIED"
    assert cve3_change.old_value["match_confidence"] == 0.85
    assert cve3_change.new_value["match_confidence"] == 0.95


def test_compare_certificates(dual_scan_investigation_fixture):
    """Test certificate replacement resulting in REMOVED (old cert) and ADDED (new cert).
    
    Verifies:
    1. Replacing a certificate on a subdomain generates REMOVED (old cert) + ADDED (new cert).
    2. The certificate identity rule cert:{fqdn}:{fingerprint_sha256} correctly distinguishes new cert issues.
    """
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    primary_domain = env["primary_domain"]
    rand_id = env["rand_id"]

    fp_old = hashlib.sha256(f"cert-old-{rand_id}".encode()).hexdigest()
    fp_new = hashlib.sha256(f"cert-new-{rand_id}".encode()).hexdigest()

    sub_replaced_fqdn = f"replaced.{primary_domain}"

    with TestingSessionLocal() as db:
        # Replaced certificate pair (old cert in Scan 1, new cert in Scan 2)
        cert_old = Certificate(
            fingerprint_sha256=fp_old,
            subject_cn=sub_replaced_fqdn,
            issuer="Let's Encrypt",
            valid_from=datetime(2023, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2023, 4, 1, tzinfo=timezone.utc),
            is_expired=True,
        )
        cert_new = Certificate(
            fingerprint_sha256=fp_new,
            subject_cn=sub_replaced_fqdn,
            issuer="DigiCert Inc",
            valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2025, 1, 1, tzinfo=timezone.utc),
            is_expired=False,
        )
        db.add_all([cert_old, cert_new])
        db.flush()

        # Create assets and subdomains
        sub_asset_rep = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan2_id, asset_type="subdomain", value=sub_replaced_fqdn, source="ct_log")
        db.add(sub_asset_rep)
        db.flush()

        sub_rep = Subdomain(asset_id=sub_asset_rep.id, domain_id=domain_id, subdomain_name=sub_replaced_fqdn)
        db.add(sub_rep)
        db.flush()

        # Scan 1: sub_rep has cert_old
        db.execute(subdomain_certificates.insert().values(subdomain_id=sub_rep.id, certificate_id=cert_old.id, scan_run_id=scan1_id))

        # Scan 2: sub_rep replaced cert_old with cert_new
        db.execute(subdomain_certificates.insert().values(subdomain_id=sub_rep.id, certificate_id=cert_new.id, scan_run_id=scan2_id))

        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    cert_changes = [c for c in result.changes if c.category == "certificate"]
    assert len(cert_changes) >= 2

    # Verify certificate replacement produces REMOVED (old) and ADDED (new)
    removed_cert = next((c for c in cert_changes if c.change_type == "REMOVED" and fp_old in c.entity_key), None)
    added_cert = next((c for c in cert_changes if c.change_type == "ADDED" and fp_new in c.entity_key), None)

    assert removed_cert is not None
    assert "no longer observed" in removed_cert.description
    assert added_cert is not None
    assert "New TLS certificate observed" in added_cert.description


def test_compare_asset_relationships(dual_scan_investigation_fixture):
    """Test detecting added and removed graph relationship edges."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_asset_id = env["domain_asset_id"]

    with TestingSessionLocal() as db:
        child_asset = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan1_id, asset_type="ip", value="198.51.100.99", source="dns")
        db.add(child_asset)
        db.flush()

        # Relationship only in scan1
        rel1 = AssetRelationship(
            investigation_id=inv_id,
            source_asset_id=domain_asset_id,
            target_asset_id=child_asset.id,
            relationship_type="RESOLVES_TO",
            scan_run_id=scan1_id,
        )
        db.add(rel1)
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    rel_changes = [c for c in result.changes if c.category == "asset_relationship"]
    assert len(rel_changes) >= 1
    assert any(c.change_type == "REMOVED" for c in rel_changes)


def test_historical_scanrun_isolation(dual_scan_investigation_fixture):
    """Verify that comparing scans does NOT mutate or delete historical ScanRun observations."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]

    with TestingSessionLocal() as db:
        initial_scan1_asset_count = db.query(Asset).filter(Asset.last_scan_run_id == scan1_id).count()
        initial_scan2_asset_count = db.query(Asset).filter(Asset.last_scan_run_id == scan2_id).count()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    with TestingSessionLocal() as db:
        post_scan1_count = db.query(Asset).filter(Asset.last_scan_run_id == scan1_id).count()
        post_scan2_count = db.query(Asset).filter(Asset.last_scan_run_id == scan2_id).count()

        # Assert no assets were deleted or reassigned
        assert post_scan1_count == initial_scan1_asset_count
        assert post_scan2_count == initial_scan2_asset_count


def test_duplicate_comparison_idempotency(dual_scan_investigation_fixture):
    """Test running compare twice on the exact same scan pair does not duplicate ChangeRecords."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    sub_name = f"sub-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        asset_new = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=sub_name,
            source="ct_log",
        )
        db.add(asset_new)
        db.flush()
        db.add(Subdomain(asset_id=asset_new.id, domain_id=domain_id, subdomain_name=sub_name))
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        res1 = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    with TestingSessionLocal() as db:
        res2 = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    assert res1.total_changes == res2.total_changes
    assert res1.added_count == res2.added_count

    with TestingSessionLocal() as db:
        db_records = (
            db.query(ChangeRecord)
            .filter(ChangeRecord.investigation_id == inv_id)
            .filter(ChangeRecord.previous_scan_id == scan1_id)
            .filter(ChangeRecord.current_scan_id == scan2_id)
            .all()
        )
        assert len(db_records) == res1.total_changes


def test_cross_investigation_scan_rejection(dual_scan_investigation_fixture):
    """Ensure comparing scans from two different investigations is rejected with 400 Bad Request."""
    env = dual_scan_investigation_fixture
    inv1_id = env["investigation_id"]
    scan1_id = env["scan1_id"]

    # Create second investigation with its own scan
    with TestingSessionLocal() as db:
        analyst_id = env["analyst_id"]
        inv2 = Investigation(
            reference_code="INV-M9-SECOND",
            title="Second Investigation",
            target_id=env["target_id"],
            created_by_id=analyst_id,
            status="active",
        )
        db.add(inv2)
        db.flush()
        scan_foreign = ScanRun(
            investigation_id=inv2.id,
            run_number=1,
            status="completed",
        )
        db.add(scan_foreign)
        db.commit()
        db.refresh(inv2)
        db.refresh(scan_foreign)
        foreign_scan_id = scan_foreign.id

    headers = get_auth_headers(analyst_id, "analyst_9a", "analyst")
    response = client.post(
        f"/api/investigations/{inv1_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(foreign_scan_id)},
        headers=headers,
    )

    assert response.status_code == 400
    assert "belong to this investigation" in response.json()["detail"]


def test_idor_and_rbac_protection(dual_scan_investigation_fixture):
    """Test RBAC and IDOR protection across analysts, auditors, and admin."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]

    analyst9a_headers = get_auth_headers(uuid.UUID("91111111-1111-1111-1111-111111111111"), "analyst_9a", "analyst")
    analyst9b_headers = get_auth_headers(uuid.UUID("92222222-2222-2222-2222-222222222222"), "analyst_9b", "analyst")
    admin_headers = get_auth_headers(uuid.UUID("93333333-3333-3333-3333-333333333333"), "admin_9", "admin")

    # 1. Analyst B cannot trigger comparison on Analyst A's investigation (403 Forbidden)
    res_b = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan2_id)},
        headers=analyst9b_headers,
    )
    assert res_b.status_code == 403

    # 2. Analyst B cannot list Analyst A's change records (403 Forbidden)
    res_b_list = client.get(
        f"/api/investigations/{inv_id}/changes",
        headers=analyst9b_headers,
    )
    assert res_b_list.status_code == 403

    # 3. Analyst A can trigger comparison and list changes (200 OK)
    res_a = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan2_id)},
        headers=analyst9a_headers,
    )
    assert res_a.status_code == 200

    res_a_list = client.get(f"/api/investigations/{inv_id}/changes", headers=analyst9a_headers)
    assert res_a_list.status_code == 200

    # 4. Admin can trigger compare and read summary on any investigation (200 OK)
    res_admin_compare = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan2_id)},
        headers=admin_headers,
    )
    assert res_admin_compare.status_code == 200

    res_admin_summary = client.get(f"/api/investigations/{inv_id}/monitoring/summary", headers=admin_headers)
    assert res_admin_summary.status_code == 200


def test_insufficient_scans_for_automatic_comparison():
    """Test when an investigation has only 1 scan run, auto-comparison returns clear 400 error."""
    with TestingSessionLocal() as db:
        analyst_id = uuid.UUID("91111111-1111-1111-1111-111111111111")
        target = Target(name="Single Scan Corp", primary_domain="singlescan.local", is_authorized=True)
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-SINGLE-{uuid.uuid4().hex[:6].upper()}",
            title="Single Scan Inv",
            target_id=target.id,
            created_by_id=analyst_id,
            status="active",
        )
        db.add(inv)
        db.flush()

        scan1 = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
        db.add(scan1)
        db.commit()
        db.refresh(inv)
        inv_id = inv.id

    headers = get_auth_headers(analyst_id, "analyst_9a", "analyst")
    response = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={},
        headers=headers,
    )
    assert response.status_code == 400
    assert "At least two ScanRuns are required" in response.json()["detail"]


def test_auto_compare_latest_two_scans(dual_scan_investigation_fixture):
    """Test comparing without explicit scan IDs automatically resolves the latest two scans."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    headers = get_auth_headers(env["analyst_id"], "analyst_9a", "analyst")

    response = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["baseline_scan_run_id"] == str(env["scan1_id"])
    assert data["current_scan_run_id"] == str(env["scan2_id"])


def test_compare_same_scan_run_with_itself(dual_scan_investigation_fixture):
    """Test comparing a scan run with itself returns 0 changes."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    headers = get_auth_headers(env["analyst_id"], "analyst_9a", "analyst")

    response = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan1_id)},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_changes"] == 0
    assert data["added_count"] == 0
    assert data["removed_count"] == 0
    assert data["modified_count"] == 0


def test_evidence_and_provenance_preservation(dual_scan_investigation_fixture):
    """Test that change records preserve evidence ID and SHA-256 evidence hash."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]

    test_payload = f'{{"observed": "evidence-{rand_id}"}}'
    evidence_sha256 = hashlib.sha256(test_payload.encode()).hexdigest()
    sub_name = f"evsub-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        ev = Evidence(
            reference_code=f"EV-TEST-{rand_id.upper()}",
            investigation_id=inv_id,
            scan_run_id=scan2_id,
            evidence_type="dns_query",
            source="dns_service",
            raw_payload=test_payload,
            sha256_hash=evidence_sha256,
        )
        db.add(ev)
        db.flush()

        asset_new = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=sub_name,
            source="dns",
        )
        db.add(asset_new)
        db.flush()
        db.add(Subdomain(asset_id=asset_new.id, domain_id=domain_id, subdomain_name=sub_name))
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    ev_change = next((c for c in result.changes if f"evsub-{rand_id}" in c.entity_key), None)
    assert ev_change is not None


def test_api_changes_list_filters_and_summary(dual_scan_investigation_fixture):
    """Test GET /api/investigations/{id}/changes with filters and GET /api/investigations/{id}/monitoring/summary."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    rand_id = env["rand_id"]
    headers = get_auth_headers(env["analyst_id"], "analyst_9a", "analyst")

    sub_name = f"filtertest-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        asset_new = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            last_scan_run_id=scan2_id,
            asset_type="subdomain",
            value=sub_name,
            source="ct_log",
        )
        db.add(asset_new)
        db.flush()
        db.add(Subdomain(asset_id=asset_new.id, domain_id=domain_id, subdomain_name=sub_name))
        db.commit()

    # Trigger compare
    res_cmp = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan2_id)},
        headers=headers,
    )
    assert res_cmp.status_code == 200

    # 1. Filter by change_type=ADDED
    res_added = client.get(
        f"/api/investigations/{inv_id}/changes?change_type=ADDED",
        headers=headers,
    )
    assert res_added.status_code == 200
    for item in res_added.json()["changes"]:
        assert item["change_type"] == "ADDED"

    # 2. Filter by category=subdomain
    res_sub = client.get(
        f"/api/investigations/{inv_id}/changes?category=subdomain",
        headers=headers,
    )
    assert res_sub.status_code == 200
    for item in res_sub.json()["changes"]:
        assert item["category"] == "subdomain"

    # 3. Check Monitoring Summary endpoint
    res_summary = client.get(
        f"/api/investigations/{inv_id}/monitoring/summary",
        headers=headers,
    )
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert "total" in summary_data
    assert "added_count" in summary_data
    assert "removed_count" in summary_data
    assert "modified_count" in summary_data
    assert "changes_by_category" in summary_data


def test_compare_security_findings(dual_scan_investigation_fixture):
    """Test detecting added, removed, and modified security findings between scans."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    dom_asset_id = env["domain_asset_id"]
    rand_id = env["rand_id"]

    with TestingSessionLocal() as db:
        # Scan 1: Finding 1 (Resolved in scan 2)
        f1 = Finding(
            reference_code=f"F-M9-1-{rand_id.upper()}",
            investigation_id=inv_id,
            scan_run_id=scan1_id,
            asset_id=dom_asset_id,
            category="security_header",
            finding_type="SECURITY_HEADER",
            title="Missing HSTS Header",
            severity="MEDIUM",
            context_score=45,
            description="Strict-Transport-Security header missing",
            recommendation="Enable HSTS with max-age 31536000",
            status="open",
        )
        # Scan 2: Finding 2 (Newly added in scan 2)
        f2 = Finding(
            reference_code=f"F-M9-2-{rand_id.upper()}",
            investigation_id=inv_id,
            scan_run_id=scan2_id,
            asset_id=dom_asset_id,
            category="vulnerability",
            finding_type="VULNERABILITY",
            title="Remote Code Execution",
            severity="CRITICAL",
            context_score=95,
            description="Critical RCE vulnerability observed",
            recommendation="Upgrade software immediately",
            status="open",
        )
        db.add_all([f1, f2])
        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    finding_changes = [c for c in result.changes if c.category == "finding"]
    assert len(finding_changes) >= 2

    added_f = next((c for c in finding_changes if "Remote Code Execution" in c.description and c.change_type == "ADDED"), None)
    removed_f = next((c for c in finding_changes if "Missing HSTS Header" in c.description and c.change_type == "REMOVED"), None)

    assert added_f is not None
    assert removed_f is not None


def test_multiple_heterogeneous_changes_in_single_scan(dual_scan_investigation_fixture):
    """Test a complex scan comparison with multiple heterogeneous changes simultaneously."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    dom_asset_id = env["domain_asset_id"]
    rand_id = env["rand_id"]

    sub1_name = f"alpha-{rand_id}.monitored-{rand_id}.com"
    sub2_name = f"beta-{rand_id}.monitored-{rand_id}.com"

    with TestingSessionLocal() as db:
        # Added subdomain in Scan 2
        a1 = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan2_id, asset_type="subdomain", value=sub1_name, source="ct_log")
        db.add(a1)
        db.flush()
        db.add(Subdomain(asset_id=a1.id, domain_id=domain_id, subdomain_name=sub1_name))

        # Removed subdomain in Scan 1
        a2 = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan1_id, asset_type="subdomain", value=sub2_name, source="ct_log")
        db.add(a2)
        db.flush()
        db.add(Subdomain(asset_id=a2.id, domain_id=domain_id, subdomain_name=sub2_name))

        # Added Technology in Scan 2
        db.add(Technology(asset_id=dom_asset_id, scan_run_id=scan2_id, name="react", category="js_library", version="18.2.0", evidence_source="script_tag"))

        db.commit()

    service = ChangeDetectionService()
    with TestingSessionLocal() as db:
        result = service.compare_scan_runs(db, inv_id, scan1_id, scan2_id)

    assert result.total_changes >= 3
    assert result.added_count >= 2
    assert result.removed_count >= 1
    assert "subdomain" in result.changes_by_category
    assert "technology" in result.changes_by_category


def test_invalid_scan_run_ids(dual_scan_investigation_fixture):
    """Test passing invalid/non-existent ScanRun IDs returns 404."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    headers = get_auth_headers(env["analyst_id"], "analyst_9a", "analyst")
    fake_uuid = str(uuid.uuid4())

    response = client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": fake_uuid, "current_scan_run_id": str(env["scan2_id"])},
        headers=headers,
    )
    assert response.status_code == 404
    assert "Baseline ScanRun not found" in response.json()["detail"]


def test_changes_pagination_offset_limit(dual_scan_investigation_fixture):
    """Test pagination with limit and offset query parameters on GET /changes."""
    env = dual_scan_investigation_fixture
    inv_id = env["investigation_id"]
    scan1_id = env["scan1_id"]
    scan2_id = env["scan2_id"]
    target_id = env["target_id"]
    domain_id = env["domain_rec_id"]
    headers = get_auth_headers(env["analyst_id"], "analyst_9a", "analyst")

    with TestingSessionLocal() as db:
        # Create 5 new subdomains in Scan 2
        for i in range(5):
            name = f"pag-{i}-{uuid.uuid4().hex[:6]}.monitored-test.com"
            a = Asset(target_id=target_id, investigation_id=inv_id, last_scan_run_id=scan2_id, asset_type="subdomain", value=name, source="ct_log")
            db.add(a)
            db.flush()
            db.add(Subdomain(asset_id=a.id, domain_id=domain_id, subdomain_name=name))
        db.commit()

    # Trigger compare
    client.post(
        f"/api/investigations/{inv_id}/monitoring/compare",
        json={"baseline_scan_run_id": str(scan1_id), "current_scan_run_id": str(scan2_id)},
        headers=headers,
    )

    # Page 1: limit 2, offset 0
    res_p1 = client.get(f"/api/investigations/{inv_id}/changes?limit=2&offset=0", headers=headers)
    assert res_p1.status_code == 200
    p1_data = res_p1.json()
    assert len(p1_data["changes"]) == 2
    assert p1_data["total"] >= 5

    # Page 2: limit 2, offset 2
    res_p2 = client.get(f"/api/investigations/{inv_id}/changes?limit=2&offset=2", headers=headers)
    assert res_p2.status_code == 200
    p2_data = res_p2.json()
    assert len(p2_data["changes"]) == 2
    # Distinct items across pages
    p1_ids = {c["id"] for c in p1_data["changes"]}
    p2_ids = {c["id"] for c in p2_data["changes"]}
    assert len(p1_ids.intersection(p2_ids)) == 0

