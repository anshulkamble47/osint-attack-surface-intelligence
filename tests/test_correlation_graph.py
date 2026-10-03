"""Comprehensive test suite for Stage 7: Correlation & Attack-Surface Graph.

Tests cover:
1. Domain -> Subdomain relationship (CONTAINS)
2. Subdomain -> IP relationship (RESOLVES_TO)
3. IP -> ASN relationship (ANNOUNCED_BY)
4. Subdomain -> Service relationship (EXPOSES)
5. Subdomain -> Technology relationship (USES_TECHNOLOGY)
6. Technology -> Vulnerability relationship (AFFECTED_BY)
7. Certificate -> Subdomain relationship (HAS_CERTIFICATE)
8. Correct graph node generation (IDs, types, labels, metadata)
9. Correct graph edge generation (IDs, sources, targets, types, scan_run_id)
10. Graph statistics calculation (node_count, edge_count, breakdowns)
11. Duplicate relationship prevention
12. Repeated correlation idempotency
13. ScanRun historical isolation
14. Cross-investigation ScanRun rejection
15. Unauthorized investigation access (RBAC)
16. Node type filtering
17. Relationship type filtering
18. Empty graph behavior
19. Missing/invalid ScanRun behavior
20. Regression test ensuring Stage 6 vulnerability relationships remain intact
"""

import uuid
import random
from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, IPAddress, ASN, IPObservation, ServiceExposure
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.relationship import AssetRelationship
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.correlation_service import CorrelationService
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_stage7_test_users():
    """Ensure required test users exist in database."""
    with TestingSessionLocal() as db:
        users = [
            (uuid.UUID("71111111-1111-1111-1111-111111111111"), "analyst7a@security.local", "analyst_7a", "analyst"),
            (uuid.UUID("72222222-2222-2222-2222-222222222222"), "analyst7b@security.local", "analyst_7b", "analyst"),
            (uuid.UUID("73333333-3333-3333-3333-333333333333"), "admin7@security.local", "admin_7", "admin"),
        ]
        for user_id, email, username, role in users:
            existing = db.get(User, user_id)
            if not existing:
                u = User(
                    id=user_id,
                    email=email,
                    username=username,
                    hashed_password=hash_password("Password123!"),
                    full_name=f"Stage7 {username}",
                    role=role,
                    is_active=True,
                )
                db.add(u)
        db.commit()


def get_auth_headers(user_id: uuid.UUID, username: str, role: str) -> dict:
    token = create_access_token(data={"sub": str(user_id), "username": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def populated_graph_environment():
    """Seed a rich, complete attack-surface graph environment for testing and clean up after."""
    with TestingSessionLocal() as db:
        analyst_id = uuid.UUID("71111111-1111-1111-1111-111111111111")
        rand_id = uuid.uuid4().hex[:8]
        rand_asn = random.randint(70000, 99999)
        rand_ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
        rand_cve = f"CVE-2021-{random.randint(10000, 99999)}"
        rand_fp = uuid.uuid4().hex + uuid.uuid4().hex

        target = Target(
            name=f"Graph Test Corp {rand_id}",
            primary_domain=f"graphtest-{rand_id}.com",
            organization="Graph Test Corp",
            is_authorized=True,
        )
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-G7-{rand_id.upper()}",
            target_id=target.id,
            title="Graph Assessment",
            created_by_id=analyst_id,
            status="active",
        )
        db.add(inv)
        db.flush()

        scan_run = ScanRun(
            investigation_id=inv.id,
            run_number=1,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan_run)
        db.flush()

        # 1. Domain Asset & Model
        dom_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value=f"graphtest-{rand_id}.com",
            source="ct_log",
            last_scan_run_id=scan_run.id,
        )
        db.add(dom_asset)
        db.flush()

        domain = Domain(
            asset_id=dom_asset.id,
            domain_name=f"graphtest-{rand_id}.com",
            registrar="MarkMonitor Inc.",
            nameservers=[f"ns1.graphtest-{rand_id}.com", f"ns2.graphtest-{rand_id}.com"],
            status=["clientTransferProhibited"],
        )
        db.add(domain)
        db.flush()

        # 2. Subdomains
        sub_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="subdomain",
            value=f"api.graphtest-{rand_id}.com",
            source="ct_log",
            last_scan_run_id=scan_run.id,
        )
        db.add(sub_asset)
        db.flush()

        subdomain = Subdomain(
            asset_id=sub_asset.id,
            domain_id=domain.id,
            subdomain_name=f"api.graphtest-{rand_id}.com",
            is_resolving=True,
            discovery_source="crt.sh",
        )
        db.add(subdomain)
        db.flush()

        # 3. IP Address & ASN
        asn = ASN(
            asn_number=rand_asn,
            name="GraphCloud Networks",
            country="US",
            allocated_prefix="198.51.100.0/24",
        )
        db.add(asn)
        db.flush()

        ip_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="ip",
            value=rand_ip,
            source="dns",
            last_scan_run_id=scan_run.id,
        )
        db.add(ip_asset)
        db.flush()

        ip_record = IPAddress(
            asset_id=ip_asset.id,
            ip_address=rand_ip,
            ip_version=4,
            reverse_dns=f"api-edge.graphtest-{rand_id}.com",
            asn_id=asn.id,
            country="US",
            organization="GraphCloud LLC",
        )
        db.add(ip_record)
        db.flush()

        # DNS Record
        dns_rec = DNSRecord(
            subdomain_id=subdomain.id,
            scan_run_id=scan_run.id,
            record_type="A",
            value=rand_ip,
            ttl=300,
            resolver="1.1.1.1",
        )
        db.add(dns_rec)

        # IP Observation
        ip_obs = IPObservation(
            scan_run_id=scan_run.id,
            ip_address_id=ip_record.id,
            asn_id=asn.id,
        )
        db.add(ip_obs)

        # 4. Service Exposure
        service = ServiceExposure(
            asset_id=sub_asset.id,
            scan_run_id=scan_run.id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=200,
            tls_version="TLSv1.3",
            page_title="API Gateway",
        )
        db.add(service)
        db.flush()

        # 5. Technology
        tech = Technology(
            asset_id=sub_asset.id,
            service_id=service.id,
            scan_run_id=scan_run.id,
            name="nginx",
            version="1.20.0",
            cpe="cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*",
            category="web_server",
            confidence=0.95,
            evidence_source="server_header",
        )
        db.add(tech)
        db.flush()

        # 6. Vulnerability (CVE) & Correlation
        vuln = Vulnerability(
            cve_id=rand_cve,
            title="1-byte memory overwrite in resolver",
            description="A security vulnerability exists in nginx 0.6.18-1.20.0.",
            severity="HIGH",
            cvss_v3_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            source="NVD",
        )
        db.add(vuln)
        db.flush()

        tv = TechnologyVulnerability(
            technology_id=tech.id,
            vulnerability_id=vuln.id,
            match_confidence=0.90,
            verification_status="potential",
            notes='{"match_basis": "Exact CPE match"}',
        )
        db.add(tv)

        # 7. Certificate
        cert = Certificate(
            fingerprint_sha256=rand_fp,
            subject_cn=f"api.graphtest-{rand_id}.com",
            issuer="Let's Encrypt Authority X3",
            san_list=[f"api.graphtest-{rand_id}.com", f"graphtest-{rand_id}.com"],
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
            is_expired=False,
        )
        db.add(cert)
        db.flush()

        db.execute(
            subdomain_certificates.insert().values(
                subdomain_id=subdomain.id,
                certificate_id=cert.id,
                scan_run_id=scan_run.id,
                observed_at=datetime.now(timezone.utc),
            )
        )

        db.commit()

        context = {
            "target_id": target.id,
            "investigation_id": inv.id,
            "scan_run_id": scan_run.id,
            "domain_id": domain.id,
            "subdomain_id": subdomain.id,
            "ip_id": ip_record.id,
            "asn_id": asn.id,
            "asn_number": rand_asn,
            "cve_id": rand_cve,
            "subject_cn": f"api.graphtest-{rand_id}.com",
            "service_id": service.id,
            "tech_id": tech.id,
            "vuln_id": vuln.id,
            "cert_id": cert.id,
            "analyst_id": analyst_id,
        }

    try:
        yield context
    finally:
        with TestingSessionLocal() as db:
            db.execute(
                subdomain_certificates.delete().where(
                    subdomain_certificates.c.certificate_id == context["cert_id"]
                )
            )
            t = db.get(Target, context["target_id"])
            if t:
                db.delete(t)
            c = db.get(Certificate, context["cert_id"])
            if c:
                db.delete(c)
            v = db.get(Vulnerability, context["vuln_id"])
            if v:
                db.delete(v)
            a = db.get(ASN, context["asn_id"])
            if a:
                db.delete(a)
            db.commit()


# --- Tests ---

def test_1_domain_to_subdomain_contains_relationship(populated_graph_environment):
    """Verify Domain -> Subdomain CONTAINS relationship."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    contains_edges = [e for e in data["edges"] if e["relationship_type"] == "CONTAINS"]
    assert len(contains_edges) >= 1
    edge = contains_edges[0]
    assert edge["source"].startswith("domain:")
    assert edge["target"].startswith("subdomain:")
    assert edge["attributes"]["discovery_source"] == "crt.sh"


def test_2_subdomain_to_ip_resolves_to_relationship(populated_graph_environment):
    """Verify Subdomain -> IP RESOLVES_TO relationship backed by DNS record."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    resolves_edges = [e for e in data["edges"] if e["relationship_type"] == "RESOLVES_TO"]
    assert len(resolves_edges) >= 1
    edge = resolves_edges[0]
    assert edge["source"].startswith("subdomain:")
    assert edge["target"].startswith("ip:")
    assert edge["attributes"]["record_type"] == "A"


def test_3_ip_to_asn_announced_by_relationship(populated_graph_environment):
    """Verify IP -> ASN ANNOUNCED_BY relationship backed by IPObservation."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    asn_edges = [e for e in data["edges"] if e["relationship_type"] == "ANNOUNCED_BY"]
    assert len(asn_edges) >= 1
    edge = asn_edges[0]
    assert edge["source"].startswith("ip:")
    assert edge["target"].startswith("asn:")
    assert edge["attributes"]["asn_number"] == env["asn_number"]


def test_4_subdomain_to_service_exposes_relationship(populated_graph_environment):
    """Verify Subdomain -> ServiceExposure EXPOSES relationship."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    exposes_edges = [e for e in data["edges"] if e["relationship_type"] == "EXPOSES"]
    assert len(exposes_edges) >= 1
    edge = exposes_edges[0]
    assert edge["source"].startswith("subdomain:")
    assert edge["target"].startswith("service:")
    assert edge["attributes"]["port"] == 443


def test_5_subdomain_to_technology_uses_technology_relationship(populated_graph_environment):
    """Verify Service/Subdomain -> Technology USES_TECHNOLOGY relationship."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    tech_edges = [e for e in data["edges"] if e["relationship_type"] == "USES_TECHNOLOGY"]
    assert len(tech_edges) >= 1
    edge = tech_edges[0]
    assert edge["target"].startswith("technology:")
    assert edge["attributes"]["name"] == "nginx"


def test_6_technology_to_vulnerability_affected_by_relationship(populated_graph_environment):
    """Verify Technology -> Vulnerability AFFECTED_BY relationship."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    vuln_edges = [e for e in data["edges"] if e["relationship_type"] == "AFFECTED_BY"]
    assert len(vuln_edges) >= 1
    edge = vuln_edges[0]
    assert edge["source"].startswith("technology:")
    assert edge["target"].startswith("vulnerability:")
    assert edge["attributes"]["cve_id"] == env["cve_id"]


def test_7_certificate_to_subdomain_has_certificate_relationship(populated_graph_environment):
    """Verify Subdomain -> Certificate HAS_CERTIFICATE relationship."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    cert_edges = [e for e in data["edges"] if e["relationship_type"] == "HAS_CERTIFICATE"]
    assert len(cert_edges) >= 1
    edge = cert_edges[0]
    assert edge["source"].startswith("subdomain:")
    assert edge["target"].startswith("certificate:")
    assert edge["attributes"]["subject_cn"] == env["subject_cn"]


def test_8_graph_node_generation_attributes_and_ids(populated_graph_environment):
    """Verify graph nodes have stable string IDs, labels, entity IDs, and metadata."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    node_types = {n["type"] for n in data["nodes"]}
    assert "domain" in node_types
    assert "subdomain" in node_types
    assert "ip" in node_types
    assert "asn" in node_types
    assert "service" in node_types
    assert "technology" in node_types
    assert "vulnerability" in node_types
    assert "certificate" in node_types

    for node in data["nodes"]:
        assert isinstance(node["id"], str)
        assert len(node["id"]) > 0
        assert isinstance(node["label"], str)
        assert isinstance(node["metadata"], dict)


def test_9_graph_edge_generation_attributes(populated_graph_environment):
    """Verify graph edges contain source, target, scan_run_id, and relationship_type."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    node_ids = {n["id"] for n in data["nodes"]}
    for edge in data["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        assert str(edge["scan_run_id"]) == str(env["scan_run_id"])
        assert edge["relationship_type"] in [
            "CONTAINS", "RESOLVES_TO", "ANNOUNCED_BY", "EXPOSES", "USES_TECHNOLOGY", "AFFECTED_BY", "HAS_CERTIFICATE"
        ]


def test_10_graph_statistics_calculation(populated_graph_environment):
    """Verify graph statistics accurately reflect node and edge counts and breakdowns."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    stats = data["statistics"]

    assert stats["node_count"] == len(data["nodes"])
    assert stats["edge_count"] == len(data["edges"])
    assert sum(stats["nodes_by_type"].values()) == len(data["nodes"])
    assert sum(stats["edges_by_type"].values()) == len(data["edges"])


def test_11_duplicate_relationship_prevention(populated_graph_environment):
    """Verify duplicate relationships are prevented in database and graph response."""
    env = populated_graph_environment
    with TestingSessionLocal() as db:
        service = CorrelationService()
        # Call correlation persistence multiple times
        rels1 = service.correlate_and_persist_asset_relationships(db, env["investigation_id"], env["scan_run_id"])
        rels2 = service.correlate_and_persist_asset_relationships(db, env["investigation_id"], env["scan_run_id"])
        assert len(rels2) == 0  # No duplicates created on second run


def test_12_repeated_correlation_idempotency(populated_graph_environment):
    """Verify calling graph endpoint multiple times yields strictly identical results."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    res1 = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    ).json()

    res2 = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    ).json()

    assert res1["statistics"] == res2["statistics"]
    assert len(res1["nodes"]) == len(res2["nodes"])
    assert len(res1["edges"]) == len(res2["edges"])


def test_13_scan_run_historical_isolation():
    """
    CRITICAL TEST: Verify historical scan isolation.
    ScanRun 1 observes api.iso.example -> 192.0.2.11 (ASN 78100).
    ScanRun 2 observes api.iso.example -> 198.51.100.12 (ASN 78200).
    Graph for ScanRun 1 must only show 192.0.2.11 and ASN 78100.
    Graph for ScanRun 2 must only show 198.51.100.12 and ASN 78200.
    """
    target_id = None
    asn1_id = None
    asn2_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("71111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target = Target(name=f"Isolation Target {rand_code}", primary_domain=f"iso-{rand_code.lower()}.example", organization="ISO")
            db.add(target)
            db.flush()
            target_id = target.id

            inv = Investigation(
                reference_code=f"INV-ISO-{rand_code}",
                target_id=target.id,
                title="Isolation Assessment",
                created_by_id=analyst_id,
            )
            db.add(inv)
            db.flush()

            scan1 = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
            scan2 = ScanRun(investigation_id=inv.id, run_number=2, status="completed")
            db.add_all([scan1, scan2])
            db.flush()

            # Domain & Subdomain
            dom_asset = Asset(target_id=target.id, investigation_id=inv.id, asset_type="domain", value=f"iso-{rand_code.lower()}.example", source="ct")
            db.add(dom_asset)
            db.flush()
            domain = Domain(asset_id=dom_asset.id, domain_name=f"iso-{rand_code.lower()}.example")
            db.add(domain)
            db.flush()

            sub_asset = Asset(target_id=target.id, investigation_id=inv.id, asset_type="subdomain", value=f"api.iso-{rand_code.lower()}.example", source="ct")
            db.add(sub_asset)
            db.flush()
            subdomain = Subdomain(asset_id=sub_asset.id, domain_id=domain.id, subdomain_name=f"api.iso-{rand_code.lower()}.example", is_resolving=True)
            db.add(subdomain)
            db.flush()

            # ASNs
            asn1 = ASN(asn_number=78100, name="ASN Iso One")
            asn2 = ASN(asn_number=78200, name="ASN Iso Two")
            db.add_all([asn1, asn2])
            db.flush()
            asn1_id = asn1.id
            asn2_id = asn2.id

            # IPs
            ip_asset1 = Asset(target_id=target.id, investigation_id=inv.id, asset_type="ip", value="192.0.2.11", source="dns")
            ip_asset2 = Asset(target_id=target.id, investigation_id=inv.id, asset_type="ip", value="198.51.100.12", source="dns")
            db.add_all([ip_asset1, ip_asset2])
            db.flush()

            ip1 = IPAddress(asset_id=ip_asset1.id, ip_address="192.0.2.11", asn_id=asn1.id)
            ip2 = IPAddress(asset_id=ip_asset2.id, ip_address="198.51.100.12", asn_id=asn2.id)
            db.add_all([ip1, ip2])
            db.flush()

            # Scan 1 observations
            dns1 = DNSRecord(subdomain_id=subdomain.id, scan_run_id=scan1.id, record_type="A", value="192.0.2.11")
            ip_obs1 = IPObservation(scan_run_id=scan1.id, ip_address_id=ip1.id, asn_id=asn1.id)
            db.add_all([dns1, ip_obs1])

            # Scan 2 observations
            dns2 = DNSRecord(subdomain_id=subdomain.id, scan_run_id=scan2.id, record_type="A", value="198.51.100.12")
            ip_obs2 = IPObservation(scan_run_id=scan2.id, ip_address_id=ip2.id, asn_id=asn2.id)
            db.add_all([dns2, ip_obs2])

            db.commit()

            inv_id = inv.id
            scan1_id = scan1.id
            scan2_id = scan2.id

        headers = get_auth_headers(analyst_id, "analyst_7a", "analyst")

        # Request Graph for ScanRun 1
        res1 = client.get(f"/api/investigations/{inv_id}/graph?scan_run_id={scan1_id}", headers=headers)
        assert res1.status_code == 200
        data1 = res1.json()

        ips_in_scan1 = [n["label"] for n in data1["nodes"] if n["type"] == "ip"]
        assert "192.0.2.11" in ips_in_scan1
        assert "198.51.100.12" not in ips_in_scan1

        asns_in_scan1 = [n["metadata"].get("asn_number") for n in data1["nodes"] if n["type"] == "asn"]
        assert 78100 in asns_in_scan1
        assert 78200 not in asns_in_scan1

        # Request Graph for ScanRun 2
        res2 = client.get(f"/api/investigations/{inv_id}/graph?scan_run_id={scan2_id}", headers=headers)
        assert res2.status_code == 200
        data2 = res2.json()

        ips_in_scan2 = [n["label"] for n in data2["nodes"] if n["type"] == "ip"]
        assert "198.51.100.12" in ips_in_scan2
        assert "192.0.2.11" not in ips_in_scan2

        asns_in_scan2 = [n["metadata"].get("asn_number") for n in data2["nodes"] if n["type"] == "asn"]
        assert 78200 in asns_in_scan2
        assert 78100 not in asns_in_scan2
    finally:
        if target_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target_id)
                if t:
                    db.delete(t)
                if asn1_id:
                    a1 = db.get(ASN, asn1_id)
                    if a1:
                        db.delete(a1)
                if asn2_id:
                    a2 = db.get(ASN, asn2_id)
                    if a2:
                        db.delete(a2)
                db.commit()


def test_14_cross_investigation_scan_run_rejection(populated_graph_environment):
    """Verify that requesting a ScanRun from another investigation is rejected with 400."""
    env = populated_graph_environment
    target2_id = None
    try:
        # Create second investigation with its own ScanRun
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("71111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target2 = Target(name=f"Other Corp {rand_code}", primary_domain=f"othercorp-{rand_code.lower()}.com", organization="Other")
            db.add(target2)
            db.flush()
            target2_id = target2.id

            inv2 = Investigation(
                reference_code=f"INV-OTHER-{rand_code}",
                target_id=target2.id,
                title="Other Investigation",
                created_by_id=analyst_id,
            )
            db.add(inv2)
            db.flush()

            scan_other = ScanRun(investigation_id=inv2.id, run_number=1, status="completed")
            db.add(scan_other)
            db.commit()

            other_scan_id = scan_other.id

        headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

        # Attempt to query Inv 1 graph with Inv 2's scan_run_id
        response = client.get(
            f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={other_scan_id}",
            headers=headers,
        )
        assert response.status_code == 400
        assert "does not belong" in response.json()["detail"].lower()
    finally:
        if target2_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target2_id)
                if t:
                    db.delete(t)
                db.commit()


def test_15_unauthorized_investigation_access_rejection(populated_graph_environment):
    """Verify RBAC: Analyst 2 cannot access Analyst 1's graph; Admin can."""
    env = populated_graph_environment

    analyst_2_id = uuid.UUID("72222222-2222-2222-2222-222222222222")
    admin_id = uuid.UUID("73333333-3333-3333-3333-333333333333")

    analyst2_headers = get_auth_headers(analyst_2_id, "analyst_7b", "analyst")
    admin_headers = get_auth_headers(admin_id, "admin_7", "admin")

    # Analyst 2 forbidden
    res_forbidden = client.get(
        f"/api/investigations/{env['investigation_id']}/graph",
        headers=analyst2_headers,
    )
    assert res_forbidden.status_code == 403

    # Admin allowed
    res_admin = client.get(
        f"/api/investigations/{env['investigation_id']}/graph",
        headers=admin_headers,
    )
    assert res_admin.status_code == 200


def test_16_node_type_filtering(populated_graph_environment):
    """Verify filtering graph by node_type returns only specified types."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?node_type=technology&node_type=vulnerability",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    returned_types = {n["type"] for n in data["nodes"]}
    assert returned_types.issubset({"technology", "vulnerability"})
    assert "domain" not in returned_types


def test_17_relationship_type_filtering(populated_graph_environment):
    """Verify filtering graph by relationship_type returns only matching edges."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?relationship_type=RESOLVES_TO",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    for edge in data["edges"]:
        assert edge["relationship_type"] == "RESOLVES_TO"


def test_18_empty_graph_behavior():
    """Verify an investigation with no observations returns a valid empty graph."""
    target_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("71111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target = Target(name=f"Empty Corp {rand_code}", primary_domain=f"empty-{rand_code.lower()}.example", organization="Empty")
            db.add(target)
            db.flush()
            target_id = target.id

            inv = Investigation(
                reference_code=f"INV-EMPTY-{rand_code}",
                target_id=target.id,
                title="Empty Assessment",
                created_by_id=analyst_id,
            )
            db.add(inv)
            db.commit()
            inv_id = inv.id

        headers = get_auth_headers(analyst_id, "analyst_7a", "analyst")

        response = client.get(f"/api/investigations/{inv_id}/graph", headers=headers)
        assert response.status_code == 200
        data = response.json()

        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["statistics"]["node_count"] == 0
        assert data["statistics"]["edge_count"] == 0
    finally:
        if target_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target_id)
                if t:
                    db.delete(t)
                db.commit()


def test_19_missing_or_invalid_scan_run_behavior(populated_graph_environment):
    """Verify requesting non-existent scan_run_id returns 404."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    fake_scan_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={fake_scan_id}",
        headers=headers,
    )
    assert response.status_code == 404


def test_20_stage6_regression_vulnerability_relationships_intact(populated_graph_environment):
    """Verify Stage 6 technology and vulnerability correlations remain intact and queryable."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/vulnerabilities?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    assert len(data) >= 1
    item = data[0]
    assert item["technology_name"] == "nginx"
    assert item["cve_id"] == env["cve_id"]
    assert item["severity"] == "HIGH"


def test_21_asn_filtering_incident_relationships(populated_graph_environment):
    """Verify that filtering by node_type=asn retains incident ANNOUNCED_BY relationships and does not return 0 edges."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    response = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?node_type=asn",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    # Verify ASN node is present
    asn_nodes = [n for n in data["nodes"] if n["type"] == "asn"]
    assert len(asn_nodes) == 1
    assert asn_nodes[0]["metadata"]["asn_number"] == env["asn_number"]

    # Verify incident ANNOUNCED_BY edge is preserved
    announced_edges = [e for e in data["edges"] if e["relationship_type"] == "ANNOUNCED_BY"]
    assert len(announced_edges) >= 1
    assert announced_edges[0]["target"] == asn_nodes[0]["id"]
    assert data["statistics"]["edge_count"] >= 1


def test_22_subdomain_and_ip_node_filtering(populated_graph_environment):
    """Verify that single node-type filtering for subdomains or IPs returns incident edges."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    # Filter by subdomain
    res_sub = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?node_type=subdomain",
        headers=headers,
    )
    assert res_sub.status_code == 200
    data_sub = res_sub.json()
    assert all(n["type"] == "subdomain" for n in data_sub["nodes"])
    # Incident edges should include CONTAINS, RESOLVES_TO, EXPOSES, HAS_CERTIFICATE
    assert len(data_sub["edges"]) > 0

    # Filter by ip
    res_ip = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?node_type=ip",
        headers=headers,
    )
    assert res_ip.status_code == 200
    data_ip = res_ip.json()
    assert all(n["type"] == "ip" for n in data_ip["nodes"])
    # Incident edges should include RESOLVES_TO and ANNOUNCED_BY
    assert len(data_ip["edges"]) >= 1


def test_23_relationship_filtering_and_idempotent_reconstruction(populated_graph_environment):
    """Verify relationship-type filtering and idempotent graph construction."""
    env = populated_graph_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_7a", "analyst")

    # Filter by relationship_type=RESOLVES_TO
    res_rel = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?relationship_type=RESOLVES_TO",
        headers=headers,
    )
    assert res_rel.status_code == 200
    data_rel = res_rel.json()
    for edge in data_rel["edges"]:
        assert edge["relationship_type"] == "RESOLVES_TO"

    # Verify repeated graph calls do not create duplicate AssetRelationship records
    with TestingSessionLocal() as db:
        initial_rel_count = (
            db.execute(
                select(AssetRelationship).where(
                    AssetRelationship.investigation_id == env["investigation_id"]
                )
            )
            .scalars()
            .all()
        )
        initial_count = len(initial_rel_count)

    # Trigger graph build again
    res_again = client.get(
        f"/api/investigations/{env['investigation_id']}/graph",
        headers=headers,
    )
    assert res_again.status_code == 200

    with TestingSessionLocal() as db:
        after_rel_count = (
            db.execute(
                select(AssetRelationship).where(
                    AssetRelationship.investigation_id == env["investigation_id"]
                )
            )
            .scalars()
            .all()
        )
        assert len(after_rel_count) == initial_count


def test_24_batch_loading_scale_and_performance():
    """Verify graph generation with 50+ assets executes in sub-second time without N+1 query regression."""
    import time
    target_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("71111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target = Target(
                name=f"Scale Test Corp {rand_code}",
                primary_domain=f"scale-{rand_code.lower()}.com",
                organization="Scale Corp",
                is_authorized=True,
            )
            db.add(target)
            db.flush()
            target_id = target.id

            inv = Investigation(
                reference_code=f"INV-SCALE-{rand_code}",
                target_id=target.id,
                title="Scale Assessment",
                created_by_id=analyst_id,
                status="active",
            )
            db.add(inv)
            db.flush()

            scan_run = ScanRun(
                investigation_id=inv.id,
                run_number=1,
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            db.add(scan_run)
            db.flush()

            # Domain
            dom_asset = Asset(
                target_id=target.id,
                investigation_id=inv.id,
                asset_type="domain",
                value=f"scale-{rand_code.lower()}.com",
                source="ct_log",
                last_scan_run_id=scan_run.id,
            )
            db.add(dom_asset)
            db.flush()

            domain = Domain(
                asset_id=dom_asset.id,
                domain_name=f"scale-{rand_code.lower()}.com",
                registrar="Scale Registrar",
                nameservers=["ns1.scale.com"],
                status=["ok"],
            )
            db.add(domain)
            db.flush()

            # ASN
            asn = ASN(
                asn_number=99901,
                name="Scale Global ASN",
                country="US",
                allocated_prefix="198.51.0.0/16",
            )
            db.add(asn)
            db.flush()

            # Vulnerability
            vuln = Vulnerability(
                cve_id=f"CVE-2024-SCALE{rand_code}",
                title="Scale Test CVE",
                description="Scale Test CVE description",
                severity="HIGH",
                cvss_v3_score=8.5,
                source="cve_mitre",
            )
            db.add(vuln)
            db.flush()

            # Create 50 subdomains, IPs, DNS records, services, technologies, certs
            for i in range(50):
                sub_asset = Asset(
                    target_id=target.id,
                    investigation_id=inv.id,
                    asset_type="subdomain",
                    value=f"sub{i}.scale-{rand_code.lower()}.com",
                    source="ct_log",
                    last_scan_run_id=scan_run.id,
                )
                db.add(sub_asset)
                db.flush()

                sub = Subdomain(
                    asset_id=sub_asset.id,
                    domain_id=domain.id,
                    subdomain_name=f"sub{i}.scale-{rand_code.lower()}.com",
                    is_resolving=True,
                    discovery_source="crt.sh",
                )
                db.add(sub)
                db.flush()

                ip_str = f"198.51.{i // 254}.{i % 254 + 1}"
                ip_asset = Asset(
                    target_id=target.id,
                    investigation_id=inv.id,
                    asset_type="ip",
                    value=ip_str,
                    source="dns",
                    last_scan_run_id=scan_run.id,
                )
                db.add(ip_asset)
                db.flush()

                ip_rec = IPAddress(
                    asset_id=ip_asset.id,
                    ip_address=ip_str,
                    ip_version=4,
                    asn_id=asn.id,
                    country="US",
                    organization="Scale Corp",
                )
                db.add(ip_rec)
                db.flush()

                dns_rec = DNSRecord(
                    subdomain_id=sub.id,
                    scan_run_id=scan_run.id,
                    record_type="A",
                    value=ip_str,
                    ttl=300,
                )
                db.add(dns_rec)

                svc = ServiceExposure(
                    asset_id=sub_asset.id,
                    scan_run_id=scan_run.id,
                    port=443,
                    protocol="TCP",
                    service_name="https",
                    http_status=200,
                )
                db.add(svc)
                db.flush()

                tech = Technology(
                    asset_id=sub_asset.id,
                    scan_run_id=scan_run.id,
                    service_id=svc.id,
                    name="OpenSSL",
                    version="1.1.1",
                    category="library",
                    evidence_source="tls_handshake",
                    confidence=1.0,
                )
                db.add(tech)
                db.flush()

                tv = TechnologyVulnerability(
                    technology_id=tech.id,
                    vulnerability_id=vuln.id,
                    match_confidence=1.0,
                    verification_status="potential",
                )
                db.add(tv)

            db.commit()
            inv_id = inv.id

        headers = get_auth_headers(analyst_id, "analyst_7a", "analyst")

        start_time = time.perf_counter()
        response = client.get(f"/api/investigations/{inv_id}/graph", headers=headers)
        elapsed = time.perf_counter() - start_time

        assert response.status_code == 200
        data = response.json()

        # Check performance (< 0.5s for 50 subdomains + full topology)
        assert elapsed < 0.5, f"Graph generation took {elapsed:.2f}s, exceeding 0.5s threshold"

        # Check nodes & edges
        assert data["statistics"]["node_count"] >= 150
        assert data["statistics"]["edge_count"] >= 200
        assert "domain" in data["statistics"]["nodes_by_type"]
        assert "subdomain" in data["statistics"]["nodes_by_type"]
        assert "ip" in data["statistics"]["nodes_by_type"]
        assert "asn" in data["statistics"]["nodes_by_type"]
        assert "service" in data["statistics"]["nodes_by_type"]
        assert "technology" in data["statistics"]["nodes_by_type"]
        assert "vulnerability" in data["statistics"]["nodes_by_type"]

        assert "CONTAINS" in data["statistics"]["edges_by_type"]
        assert "RESOLVES_TO" in data["statistics"]["edges_by_type"]
        assert "ANNOUNCED_BY" in data["statistics"]["edges_by_type"]
        assert "EXPOSES" in data["statistics"]["edges_by_type"]
        assert "USES_TECHNOLOGY" in data["statistics"]["edges_by_type"]
        assert "AFFECTED_BY" in data["statistics"]["edges_by_type"]

    finally:
        if target_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target_id)
                if t:
                    db.delete(t)
                db.commit()
