"""Comprehensive test suite for Stage 3B: Active DNS Intelligence & Reachability Probing."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
import dns.resolver
import dns.exception
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import httpx

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, ServiceExposure
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.dns_service import DNSService, DNSObservation, DNSResolutionResult
from backend.app.services.reachability_service import (
    ReachabilityService,
    ReachabilityProbeResult,
    is_public_ip,
)
from backend.app.api.investigations import get_dns_service, get_reachability_service
from tests.conftest import TestingSessionLocal

client = TestClient(app)




# --- Helper Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_dns_test_users():
    """Ensure required test users exist in database."""
    with TestingSessionLocal() as db:
        users_to_seed = [
            (uuid.UUID("11111111-1111-1111-1111-111111111111"), "analyst1@security.local", "analyst_one", "analyst"),
            (uuid.UUID("22222222-2222-2222-2222-222222222222"), "analyst2@security.local", "analyst_two", "analyst"),
            (uuid.UUID("33333333-3333-3333-3333-333333333333"), "admin@security.local", "root_admin", "admin"),
        ]
        for u_id, email, username, role in users_to_seed:
            user = db.get(User, u_id)
            if not user:
                user_by_email = db.execute(
                    db.query(User).filter(User.email == email).statement
                ).scalar_one_or_none()
                if not user_by_email:
                    db.add(User(
                        id=u_id,
                        email=email,
                        username=username,
                        hashed_password=hash_password("Password123!"),
                        full_name=username.replace("_", " ").title(),
                        role=role,
                        is_active=True,
                    ))
        db.commit()


def get_auth_headers(username: str) -> dict:
    """Generate Bearer authorization headers for a test user."""
    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
        return {"Authorization": f"Bearer {token}"}


# =====================================================================
# 1. DNS SERVICE UNIT TESTS (MOCKED)
# =====================================================================

def test_dns_service_a_record_resolution():
    """Verify resolution of IPv4 A records."""
    mock_resolver = MagicMock()
    mock_rrset = MagicMock()
    mock_rrset.ttl = 300

    mock_rdata = MagicMock()
    mock_rdata.__str__.return_value = "93.184.216.34"

    mock_answer = MagicMock()
    mock_answer.rrset = mock_rrset
    mock_answer.__iter__.return_value = [mock_rdata]

    def side_effect(qname, rtype):
        if rtype == "A":
            return mock_answer
        raise dns.resolver.NoAnswer()

    mock_resolver.resolve.side_effect = side_effect
    mock_resolver.nameservers = ["1.1.1.1"]

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("example.com")

    assert result.hostname == "example.com"
    assert result.is_resolving is True
    assert len(result.records) == 1
    assert result.records[0].record_type == "A"
    assert result.records[0].value == "93.184.216.34"
    assert result.records[0].ttl == 300
    assert result.records[0].resolver == "1.1.1.1"


def test_dns_service_aaaa_and_cname_resolution():
    """Verify resolution of IPv6 AAAA and CNAME records."""
    mock_resolver = MagicMock()
    mock_rrset = MagicMock()
    mock_rrset.ttl = 600

    mock_cname_rdata = MagicMock()
    mock_cname_rdata.target = "app.cdn.cloudflare.net."

    mock_aaaa_rdata = MagicMock()
    mock_aaaa_rdata.__str__.return_value = "2606:2800:220:1:248:1893:25c8:1946"

    mock_cname_answer = MagicMock()
    mock_cname_answer.rrset = mock_rrset
    mock_cname_answer.__iter__.return_value = [mock_cname_rdata]

    mock_aaaa_answer = MagicMock()
    mock_aaaa_answer.rrset = mock_rrset
    mock_aaaa_answer.__iter__.return_value = [mock_aaaa_rdata]

    def side_effect(qname, rtype):
        if rtype == "CNAME":
            return mock_cname_answer
        elif rtype == "AAAA":
            return mock_aaaa_answer
        raise dns.resolver.NoAnswer()

    mock_resolver.resolve.side_effect = side_effect
    mock_resolver.nameservers = ["8.8.8.8"]

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("cdn.example.com")

    assert result.is_resolving is True
    assert len(result.records) == 2
    types = [r.record_type for r in result.records]
    assert "CNAME" in types
    assert "AAAA" in types
    cname_rec = next(r for r in result.records if r.record_type == "CNAME")
    assert cname_rec.value == "app.cdn.cloudflare.net"


def test_dns_service_multiple_records_mx_ns_txt():
    """Verify collection of MX, NS, and TXT records."""
    mock_resolver = MagicMock()
    mock_rrset = MagicMock()
    mock_rrset.ttl = 3600

    # MX
    mock_mx = MagicMock()
    mock_mx.preference = 10
    mock_mx.exchange = "mail.example.com."
    mock_mx_ans = MagicMock()
    mock_mx_ans.rrset = mock_rrset
    mock_mx_ans.__iter__.return_value = [mock_mx]

    # NS
    mock_ns = MagicMock()
    mock_ns.target = "ns1.example.com."
    mock_ns_ans = MagicMock()
    mock_ns_ans.rrset = mock_rrset
    mock_ns_ans.__iter__.return_value = [mock_ns]

    # TXT
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=spf1 include:_spf.google.com ~all"]
    mock_txt_ans = MagicMock()
    mock_txt_ans.rrset = mock_rrset
    mock_txt_ans.__iter__.return_value = [mock_txt]

    def side_effect(qname, rtype):
        if rtype == "MX":
            return mock_mx_ans
        elif rtype == "NS":
            return mock_ns_ans
        elif rtype == "TXT":
            return mock_txt_ans
        raise dns.resolver.NoAnswer()

    mock_resolver.resolve.side_effect = side_effect
    mock_resolver.nameservers = ["1.1.1.1"]

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("example.com")

    assert result.is_resolving is True
    assert len(result.records) == 3
    mx_rec = next(r for r in result.records if r.record_type == "MX")
    assert mx_rec.value == "10 mail.example.com"
    ns_rec = next(r for r in result.records if r.record_type == "NS")
    assert ns_rec.value == "ns1.example.com"
    txt_rec = next(r for r in result.records if r.record_type == "TXT")
    assert txt_rec.value == "v=spf1 include:_spf.google.com ~all"


def test_dns_service_nxdomain_handling():
    """Verify NXDOMAIN error handling does not raise and sets is_resolving=False."""
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
    mock_resolver.nameservers = ["1.1.1.1"]

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("nonexistent.example.com")

    assert result.hostname == "nonexistent.example.com"
    assert result.is_resolving is False
    assert len(result.records) == 0
    assert result.error == "NXDOMAIN"


def test_dns_service_timeout_handling():
    """Verify DNS timeout error handling gracefully sets error."""
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.Timeout()
    mock_resolver.nameservers = ["1.1.1.1"]

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("timeout.example.com")

    assert result.is_resolving is False
    assert len(result.records) == 0
    assert result.error == "Query Timeout"


def test_dns_service_no_nameservers_handling():
    """Verify handling when no nameservers are reachable."""
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
    mock_resolver.nameservers = []

    service = DNSService(resolver=mock_resolver)
    result = service.resolve("broken.example.com")

    assert result.is_resolving is False
    assert result.error == "No Nameservers Available"


# =====================================================================
# 2. REACHABILITY SERVICE UNIT TESTS (MOCKED)
# =====================================================================

def test_reachability_service_successful_https_and_http():
    """Verify successful probe with status 200 and page title extraction."""
    mock_client = MagicMock()

    mock_resp_https = MagicMock()
    mock_resp_https.status_code = 200
    mock_resp_https.url = "https://app.example.com/login"
    mock_resp_https.headers = {}
    mock_resp_https.text = "<html><head><title>Secure Portal Login</title></head><body>Welcome</body></html>"

    mock_resp_http = MagicMock()
    mock_resp_http.status_code = 301
    mock_resp_http.url = "https://app.example.com/"
    mock_resp_http.headers = {}
    mock_resp_http.text = "<html><head><title>301 Moved Permanently</title></head></html>"

    def get_side_effect(url, **kwargs):
        if url.startswith("https://"):
            return mock_resp_https
        return mock_resp_http

    mock_client.get.side_effect = get_side_effect

    service = ReachabilityService(client=mock_client)
    probes = service.probe_hostname("app.example.com")


    assert len(probes) == 2

    # HTTPS probe (port 443)
    https_probe = next(p for p in probes if p.port == 443)
    assert https_probe.is_reachable is True
    assert https_probe.status_code == 200
    assert https_probe.final_url == "https://app.example.com/login"
    assert https_probe.page_title == "Secure Portal Login"
    assert https_probe.response_time_ms is not None

    # HTTP probe (port 80)
    http_probe = next(p for p in probes if p.port == 80)
    assert http_probe.is_reachable is True
    assert http_probe.status_code == 301
    assert http_probe.page_title == "301 Moved Permanently"


def test_reachability_service_connection_timeout():
    """Verify reachability service handles timeout without crashing."""
    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")

    service = ReachabilityService(client=mock_client)
    probes = service.probe_hostname("unresponsive.example.com")

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert probe.error == "Connection Timeout"
        assert probe.status_code is None


def test_reachability_service_connection_refused():
    """Verify reachability service handles network error gracefully."""
    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.ConnectError("Connection refused")

    service = ReachabilityService(client=mock_client)
    probes = service.probe_hostname("closed.example.com")

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert probe.error == "Connection Refused / Network Error"


# =====================================================================
# 3. END-TO-END INVESTIGATION RESOLUTION & REACHABILITY WORKFLOW TESTS
# =====================================================================

def test_resolve_investigation_requires_authentication():
    """Verify resolve endpoint requires authentication."""
    fake_id = uuid.uuid4()
    response = client.post(f"/api/investigations/{fake_id}/resolve")
    assert response.status_code == 401


def test_resolve_investigation_not_found():
    """Verify 404 for non-existent investigation ID."""
    fake_id = uuid.uuid4()
    headers = get_auth_headers("analyst_one")
    response = client.post(f"/api/investigations/{fake_id}/resolve", headers=headers)
    assert response.status_code == 404
    assert "Investigation not found" in response.json()["detail"]


def test_resolve_investigation_forbidden_for_other_analyst():
    """Verify analyst two cannot resolve analyst one's investigation."""
    # 1. Analyst one creates investigation
    headers_one = get_auth_headers("analyst_one")
    create_res = client.post(
        "/api/investigations",
        json={"name": "Owner Inv", "target_domain": "rbac-resolve.com"},
        headers=headers_one,
    )
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    # 2. Analyst two attempts resolution
    headers_two = get_auth_headers("analyst_two")
    resolve_res = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers_two)
    assert resolve_res.status_code == 403


def test_full_investigation_dns_resolution_and_reachability_workflow():
    """
    Verify complete Stage 3B resolution flow:
    1. Create investigation on target 'corp-target.com'
    2. Seed candidate subdomains (from CT simulation)
    3. Run active resolution endpoint
    4. Validate resolving assets become active
    5. Validate non-resolving assets remain stored but inactive
    6. Validate DNSRecords & ServiceExposures link to scan_run_id
    """
    headers = get_auth_headers("analyst_one")
    create_res = client.post(
        "/api/investigations",
        json={"name": "Corp Assessment", "target_domain": "corp-target.com"},
        headers=headers,
    )
    assert create_res.status_code == 201
    inv_data = create_res.json()
    inv_id = uuid.UUID(inv_data["id"])
    target_id = uuid.UUID(inv_data["target_id"])

    # Seed 3 candidate subdomains in DB
    with TestingSessionLocal() as db:
        domain_rec = db.query(Domain).filter(Domain.domain_name == "corp-target.com").first()

        # Candidate 1: api.corp-target.com (will resolve and be reachable)
        asset_api = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            asset_type="subdomain",
            value="api.corp-target.com",
            is_active=False,
            source="crt.sh",
        )
        db.add(asset_api)
        db.flush()
        sub_api = Subdomain(
            asset_id=asset_api.id,
            domain_id=domain_rec.id,
            subdomain_name="api.corp-target.com",
            is_resolving=False,
        )
        db.add(sub_api)

        # Candidate 2: old.corp-target.com (will NOT resolve)
        asset_old = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            asset_type="subdomain",
            value="old.corp-target.com",
            is_active=False,
            source="crt.sh",
        )
        db.add(asset_old)
        db.flush()
        sub_old = Subdomain(
            asset_id=asset_old.id,
            domain_id=domain_rec.id,
            subdomain_name="old.corp-target.com",
            is_resolving=False,
        )
        db.add(sub_old)

        db.commit()

    # Mock DNS and Reachability responses
    mock_dns = MagicMock()

    def mock_resolve(hostname, record_types=None):
        if "api.corp-target.com" in hostname:
            return DNSResolutionResult(
                hostname=hostname,
                is_resolving=True,
                records=[
                    DNSObservation(record_type="A", value="198.51.100.10", ttl=300, resolver="1.1.1.1"),
                    DNSObservation(record_type="CNAME", value="api-lb.cloud.local", ttl=300, resolver="1.1.1.1"),
                ],
            )
        elif "corp-target.com" == hostname:
            return DNSResolutionResult(
                hostname=hostname,
                is_resolving=True,
                records=[
                    DNSObservation(record_type="A", value="198.51.100.1", ttl=300, resolver="1.1.1.1"),
                ],
            )
        else:
            # old.corp-target.com NXDOMAIN
            return DNSResolutionResult(
                hostname=hostname,
                is_resolving=False,
                records=[],
                error="NXDOMAIN",
            )

    mock_dns.resolve.side_effect = mock_resolve

    mock_reachability = MagicMock()

    def mock_probe(hostname, **kwargs):
        if "api.corp-target.com" in hostname:

            return [
                ReachabilityProbeResult(
                    url=f"https://{hostname}",
                    port=443,
                    protocol="tcp",
                    service_name="https",
                    is_reachable=True,
                    status_code=200,
                    final_url=f"https://{hostname}/v1",
                    response_time_ms=45.2,
                    page_title="API Gateway",
                ),
                ReachabilityProbeResult(
                    url=f"http://{hostname}",
                    port=80,
                    protocol="tcp",
                    service_name="http",
                    is_reachable=False,
                    error="Connection Refused",
                ),
            ]
        elif "corp-target.com" == hostname:
            return [
                ReachabilityProbeResult(
                    url=f"https://{hostname}",
                    port=443,
                    protocol="tcp",
                    service_name="https",
                    is_reachable=True,
                    status_code=200,
                    final_url=f"https://{hostname}/",
                    response_time_ms=50.0,
                    page_title="Corp Home",
                ),
                ReachabilityProbeResult(
                    url=f"http://{hostname}",
                    port=80,
                    protocol="tcp",
                    service_name="http",
                    is_reachable=True,
                    status_code=301,
                    final_url=f"https://{hostname}/",
                    response_time_ms=30.0,
                ),
            ]
        return []

    mock_reachability.probe_hostname.side_effect = mock_probe

    # Execute active resolution with injected mocks
    app.dependency_overrides[get_dns_service] = lambda: mock_dns
    app.dependency_overrides[get_reachability_service] = lambda: mock_reachability
    try:
        res = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers)
    finally:
        app.dependency_overrides.pop(get_dns_service, None)
        app.dependency_overrides.pop(get_reachability_service, None)

    assert res.status_code == 200
    data = res.json()

    assert data["investigation_id"] == str(inv_id)
    assert data["target_domain"] == "corp-target.com"
    assert data["candidates_processed"] == 3  # root + api + old
    assert data["resolved"] == 2  # root + api
    assert data["not_resolved"] == 1  # old
    assert data["reachable"] == 2
    assert data["unreachable"] == 0
    assert data["dns_records_discovered"] == 3  # 1 (root A) + 2 (api A & CNAME)
    assert data["services_discovered"] == 3  # 2 (root http+https) + 1 (api https)

    scan_run_id = uuid.UUID(data["scan_run_id"])

    # Verify DB State
    with TestingSessionLocal() as db:
        # Check ScanRun status
        scan_run = db.get(ScanRun, scan_run_id)
        assert scan_run is not None
        assert scan_run.status == "completed"
        assert scan_run.total_discovered_assets == 2

        # Check Asset state for api.corp-target.com
        asset_api_db = db.query(Asset).filter(Asset.value == "api.corp-target.com", Asset.investigation_id == inv_id).first()
        assert asset_api_db.is_active is True
        assert asset_api_db.last_scan_run_id == scan_run_id

        # Check Subdomain state for api.corp-target.com
        sub_api_db = db.query(Subdomain).filter(Subdomain.asset_id == asset_api_db.id).first()
        assert sub_api_db.is_resolving is True

        # Check Non-resolving candidate was NOT deleted
        asset_old_db = db.query(Asset).filter(Asset.value == "old.corp-target.com", Asset.investigation_id == inv_id).first()
        assert asset_old_db is not None
        assert asset_old_db.is_active is False
        sub_old_db = db.query(Subdomain).filter(Subdomain.asset_id == asset_old_db.id).first()
        assert sub_old_db is not None
        assert sub_old_db.is_resolving is False

        # Check DNSRecords persisted with scan_run_id
        dns_records = db.query(DNSRecord).filter(DNSRecord.scan_run_id == scan_run_id).all()
        assert len(dns_records) == 3

        # Check ServiceExposures persisted with scan_run_id
        service_exposures = db.query(ServiceExposure).filter(ServiceExposure.scan_run_id == scan_run_id).all()
        assert len(service_exposures) == 3


def test_scan_history_preserved_across_multiple_runs():
    """
    Verify running Stage 3B resolution twice preserves previous scan observations:
    ScanRun 1 -> api.test.com -> A -> 1.1.1.1
    ScanRun 2 -> api.test.com -> A -> 2.2.2.2
    Both DNSRecords remain in the database with their respective scan_run_id.
    """
    headers = get_auth_headers("analyst_one")
    create_res = client.post(
        "/api/investigations",
        json={"name": "History Preservation Test", "target_domain": "history-test.com"},
        headers=headers,
    )
    assert create_res.status_code == 201
    inv_id = uuid.UUID(create_res.json()["id"])
    target_id = uuid.UUID(create_res.json()["target_id"])

    # Seed candidate subdomain
    with TestingSessionLocal() as db:
        domain_rec = db.query(Domain).filter(Domain.domain_name == "history-test.com").first()
        asset = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            asset_type="subdomain",
            value="sub.history-test.com",
            is_active=False,
            source="crt.sh",
        )
        db.add(asset)
        db.flush()
        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_rec.id,
            subdomain_name="sub.history-test.com",
            is_resolving=False,
        )
        db.add(sub)
        db.commit()

    # --- Run 1 ---
    mock_dns_1 = MagicMock()
    mock_dns_1.resolve.return_value = DNSResolutionResult(
        hostname="sub.history-test.com",
        is_resolving=True,
        records=[DNSObservation(record_type="A", value="1.1.1.1", ttl=300)],
    )
    mock_reach_1 = MagicMock()
    mock_reach_1.probe_hostname.return_value = []

    app.dependency_overrides[get_dns_service] = lambda: mock_dns_1
    app.dependency_overrides[get_reachability_service] = lambda: mock_reach_1
    try:
        res1 = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers)
    finally:
        app.dependency_overrides.pop(get_dns_service, None)
        app.dependency_overrides.pop(get_reachability_service, None)

    assert res1.status_code == 200
    scan1_id = uuid.UUID(res1.json()["scan_run_id"])

    # --- Run 2 ---
    mock_dns_2 = MagicMock()
    mock_dns_2.resolve.return_value = DNSResolutionResult(
        hostname="sub.history-test.com",
        is_resolving=True,
        records=[DNSObservation(record_type="A", value="2.2.2.2", ttl=300)],
    )
    mock_reach_2 = MagicMock()
    mock_reach_2.probe_hostname.return_value = []

    app.dependency_overrides[get_dns_service] = lambda: mock_dns_2
    app.dependency_overrides[get_reachability_service] = lambda: mock_reach_2
    try:
        res2 = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers)
    finally:
        app.dependency_overrides.pop(get_dns_service, None)
        app.dependency_overrides.pop(get_reachability_service, None)

    assert res2.status_code == 200
    scan2_id = uuid.UUID(res2.json()["scan_run_id"])
    assert scan1_id != scan2_id

    # Verify both scans' records are present in DB
    with TestingSessionLocal() as db:
        scan1_records = db.query(DNSRecord).filter(DNSRecord.scan_run_id == scan1_id).all()
        assert len(scan1_records) >= 1
        assert any(r.value == "1.1.1.1" for r in scan1_records)

        scan2_records = db.query(DNSRecord).filter(DNSRecord.scan_run_id == scan2_id).all()
        assert len(scan2_records) >= 1
        assert any(r.value == "2.2.2.2" for r in scan2_records)

        # Total runs for this investigation is 2
        runs = db.query(ScanRun).filter(ScanRun.investigation_id == inv_id).all()
        assert len(runs) == 2


def test_query_endpoints_dns_records_and_services():
    """Verify GET /api/investigations/{id}/dns-records and GET /api/investigations/{id}/services."""
    headers = get_auth_headers("analyst_one")
    create_res = client.post(
        "/api/investigations",
        json={"name": "Query Endpoints Test", "target_domain": "query-test.com"},
        headers=headers,
    )
    inv_id = create_res.json()["id"]

    # Run resolution
    mock_dns = MagicMock()
    mock_dns.resolve.return_value = DNSResolutionResult(
        hostname="query-test.com",
        is_resolving=True,
        records=[DNSObservation(record_type="A", value="192.0.2.1", ttl=60)],
    )
    mock_reach = MagicMock()
    mock_reach.probe_hostname.return_value = [
        ReachabilityProbeResult(
            url="https://query-test.com",
            port=443,
            protocol="tcp",
            service_name="https",
            is_reachable=True,
            status_code=200,
            page_title="Query Home",
        )
    ]

    app.dependency_overrides[get_dns_service] = lambda: mock_dns
    app.dependency_overrides[get_reachability_service] = lambda: mock_reach
    try:
        res = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers)
        assert res.status_code == 200
    finally:
        app.dependency_overrides.pop(get_dns_service, None)
        app.dependency_overrides.pop(get_reachability_service, None)

    # Query DNS records
    dns_res = client.get(f"/api/investigations/{inv_id}/dns-records", headers=headers)
    assert dns_res.status_code == 200
    records = dns_res.json()
    assert len(records) >= 1
    assert any(r["value"] == "192.0.2.1" for r in records)

    # Query Services
    svc_res = client.get(f"/api/investigations/{inv_id}/services", headers=headers)
    assert svc_res.status_code == 200
    services = svc_res.json()
    assert len(services) >= 1
    assert any(s["port"] == 443 and s["page_title"] == "Query Home" for s in services)


# =====================================================================
# 4. SSRF & REACHABILITY SECURITY AUDIT TESTS
# =====================================================================

def test_is_public_ip_validation():
    """Verify is_public_ip rejects loopback, private, link-local, multicast, and reserved ranges."""
    # Private IPv4 (RFC 1918 & CGNAT)
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("10.254.254.254") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("172.31.255.255") is False
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("192.168.100.254") is False

    # Loopback IPv4
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("127.1.2.3") is False

    # Link-local & Cloud Metadata IPv4
    assert is_public_ip("169.254.169.254") is False
    assert is_public_ip("169.254.1.1") is False

    # Multicast & Reserved IPv4
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("240.0.0.1") is False
    assert is_public_ip("0.0.0.0") is False
    assert is_public_ip("255.255.255.255") is False

    # Private & Unique Local IPv6 (fc00::/7)
    assert is_public_ip("fc00::1") is False
    assert is_public_ip("fd12:3456:789a::1") is False

    # Loopback IPv6 (::1)
    assert is_public_ip("::1") is False

    # Link-local IPv6 (fe80::/10)
    assert is_public_ip("fe80::1") is False
    assert is_public_ip("fe80::a00:27ff:fe8e:d0d") is False

    # Unspecified & Multicast IPv6
    assert is_public_ip("::") is False
    assert is_public_ip("ff02::1") is False

    # Public Routable IPv4 & IPv6
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("2606:2800:220:1:248:1893:25c8:1946") is True
    assert is_public_ip("2001:4860:4860::8888") is True


def test_ssrf_private_ipv4_probing_skipped():
    """Verify reachability service skips HTTP/HTTPS probing when resolved IPs are private (10.0.0.1)."""
    mock_client = MagicMock()
    service = ReachabilityService(client=mock_client)

    probes = service.probe_hostname("internal.target.com", resolved_ips=["10.0.0.1", "192.168.1.1"])

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert "SSRF Blocked" in (probe.error or "")
    # Verify no HTTP request was made by the client
    mock_client.get.assert_not_called()


def test_ssrf_loopback_ipv4_probing_skipped():
    """Verify reachability service skips probing when resolved IP is 127.0.0.1."""
    mock_client = MagicMock()
    service = ReachabilityService(client=mock_client)

    probes = service.probe_hostname("localhost.target.com", resolved_ips=["127.0.0.1"])

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert "SSRF Blocked" in (probe.error or "")
    mock_client.get.assert_not_called()


def test_ssrf_private_ipv6_probing_skipped():
    """Verify reachability service skips probing when resolved IP is fc00::1."""
    mock_client = MagicMock()
    service = ReachabilityService(client=mock_client)

    probes = service.probe_hostname("ipv6-internal.target.com", resolved_ips=["fc00::1"])

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert "SSRF Blocked" in (probe.error or "")
    mock_client.get.assert_not_called()


def test_ssrf_linklocal_ipv6_probing_skipped():
    """Verify reachability service skips probing when resolved IP is fe80::1."""
    mock_client = MagicMock()
    service = ReachabilityService(client=mock_client)

    probes = service.probe_hostname("ipv6-linklocal.target.com", resolved_ips=["fe80::1"])

    assert len(probes) == 2
    for probe in probes:
        assert probe.is_reachable is False
        assert "SSRF Blocked" in (probe.error or "")
    mock_client.get.assert_not_called()


def test_ssrf_public_ip_probed_normally():
    """Verify reachability service executes probe when resolved IP is public."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://public.target.com/"
    mock_resp.text = "<html><title>Public Site</title></html>"
    mock_client.get.return_value = mock_resp

    service = ReachabilityService(client=mock_client)
    probes = service.probe_hostname("public.target.com", resolved_ips=["93.184.216.34"])

    assert len(probes) == 2
    assert all(p.is_reachable is True for p in probes)
    assert mock_client.get.call_count == 2


def test_redirect_public_to_public_allowed():
    """Verify redirect from public URL to another public URL succeeds."""
    mock_client = MagicMock()

    mock_resp_301 = MagicMock()
    mock_resp_301.status_code = 301
    mock_resp_301.url = "https://public.target.com/"
    mock_resp_301.headers = {"Location": "https://public.target.com/login"}

    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.url = "https://public.target.com/login"
    mock_resp_200.text = "<html><title>Login Page</title></html>"

    def get_side_effect(url, **kwargs):
        if url == "https://public.target.com":
            return mock_resp_301
        return mock_resp_200

    mock_client.get.side_effect = get_side_effect

    service = ReachabilityService(client=mock_client)
    result = service._probe_url("https://public.target.com", port=443, service_name="https")

    assert result.is_reachable is True
    assert result.status_code == 200
    assert result.final_url == "https://public.target.com/login"
    assert result.page_title == "Login Page"


def test_redirect_public_to_private_ip_blocked():
    """Verify redirect to private IP (10.0.0.1) is blocked before making request."""
    mock_client = MagicMock()

    mock_resp_302 = MagicMock()
    mock_resp_302.status_code = 302
    mock_resp_302.url = "https://public.target.com/"
    mock_resp_302.headers = {"Location": "http://10.0.0.1/internal-admin"}

    mock_client.get.return_value = mock_resp_302

    service = ReachabilityService(client=mock_client)
    result = service._probe_url("https://public.target.com", port=443, service_name="https")

    assert result.is_reachable is False
    assert "SSRF Redirect Blocked" in (result.error or "")
    # Ensure client did not execute GET against 10.0.0.1
    assert mock_client.get.call_count == 1  # Only initial request


def test_redirect_public_to_localhost_blocked():
    """Verify redirect to 127.0.0.1 / localhost is blocked."""
    mock_client = MagicMock()

    mock_resp_302 = MagicMock()
    mock_resp_302.status_code = 302
    mock_resp_302.url = "https://public.target.com/"
    mock_resp_302.headers = {"Location": "http://127.0.0.1:8000/api/users"}

    mock_client.get.return_value = mock_resp_302

    service = ReachabilityService(client=mock_client)
    result = service._probe_url("https://public.target.com", port=443, service_name="https")

    assert result.is_reachable is False
    assert "SSRF Redirect Blocked" in (result.error or "")
    assert mock_client.get.call_count == 1


def test_redirect_max_limit_enforced():
    """Verify redirect loop is capped at max_redirects (3)."""
    mock_client = MagicMock()

    mock_resp_loop = MagicMock()
    mock_resp_loop.status_code = 302
    mock_resp_loop.url = "https://public.target.com/loop"
    mock_resp_loop.headers = {"Location": "https://public.target.com/loop"}

    mock_client.get.return_value = mock_resp_loop

    service = ReachabilityService(client=mock_client, max_redirects=3)
    result = service._probe_url("https://public.target.com/loop", port=443, service_name="https")

    # Initial request + 3 redirects = 4 GET requests
    assert mock_client.get.call_count == 4
    assert result.error == "Maximum redirect limit exceeded"


def test_large_response_body_bounded_streaming():
    """Verify reading large response bodies is capped at MAX_BODY_BYTES."""
    large_payload = ("A" * 100_000) + "<title>Hidden Far Away</title>"
    snippet = ReachabilityService._extract_title(large_payload[:8192])
    # The title beyond 8KB is not processed, keeping memory bounded
    assert snippet is None

    title_in_first_8k = "<html><head><title>Fast Portal</title></head><body>" + ("X" * 100_000)
    snippet_ok = ReachabilityService._extract_title(title_in_first_8k)
    assert snippet_ok == "Fast Portal"


def test_ssrf_private_ips_persists_dns_records_but_skips_http_in_investigation():
    """
    Verify end-to-end investigation behavior:
    1. Subdomain resolves to 10.0.0.50 (private).
    2. DNSRecord is persisted with scan_run_id.
    3. Asset is marked active and Subdomain is resolving.
    4. HTTP reachability probe is SKIPPED (no ServiceExposure created).
    """
    headers = get_auth_headers("analyst_one")
    create_res = client.post(
        "/api/investigations",
        json={"name": "SSRF Target Test", "target_domain": "ssrf-test.com"},
        headers=headers,
    )
    assert create_res.status_code == 201
    inv_id = uuid.UUID(create_res.json()["id"])
    target_id = uuid.UUID(create_res.json()["target_id"])

    # Seed candidate subdomain
    with TestingSessionLocal() as db:
        domain_rec = db.query(Domain).filter(Domain.domain_name == "ssrf-test.com").first()
        asset = Asset(
            target_id=target_id,
            investigation_id=inv_id,
            asset_type="subdomain",
            value="internal.ssrf-test.com",
            is_active=False,
            source="crt.sh",
        )
        db.add(asset)
        db.flush()
        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_rec.id,
            subdomain_name="internal.ssrf-test.com",
            is_resolving=False,
        )
        db.add(sub)
        db.commit()

    # Mock DNS resolving to private 10.0.0.50
    mock_dns = MagicMock()
    mock_dns.resolve.return_value = DNSResolutionResult(
        hostname="internal.ssrf-test.com",
        is_resolving=True,
        records=[DNSObservation(record_type="A", value="10.0.0.50", ttl=300)],
    )

    # Mock reachability service with real SSRF logic
    real_reachability = ReachabilityService(client=MagicMock())

    app.dependency_overrides[get_dns_service] = lambda: mock_dns
    app.dependency_overrides[get_reachability_service] = lambda: real_reachability
    try:
        res = client.post(f"/api/investigations/{inv_id}/resolve", headers=headers)
    finally:
        app.dependency_overrides.pop(get_dns_service, None)
        app.dependency_overrides.pop(get_reachability_service, None)

    assert res.status_code == 200
    data = res.json()
    assert data["resolved"] == 2  # root + internal
    assert data["reachable"] == 0  # 0 reachable because probing was skipped
    assert data["dns_records_discovered"] == 2  # DNS records were still persisted!
    assert data["services_discovered"] == 0  # No ServiceExposure rows created

    scan_run_id = uuid.UUID(data["scan_run_id"])

    # Verify DB State
    with TestingSessionLocal() as db:
        # Check DNSRecord exists
        records = db.query(DNSRecord).filter(DNSRecord.scan_run_id == scan_run_id).all()
        assert len(records) == 2
        assert any(r.value == "10.0.0.50" for r in records)

        # Check ServiceExposure is 0
        services = db.query(ServiceExposure).filter(ServiceExposure.scan_run_id == scan_run_id).all()
        assert len(services) == 0

        # Check Asset & Subdomain state
        asset_db = db.query(Asset).filter(Asset.value == "internal.ssrf-test.com", Asset.investigation_id == inv_id).first()
        assert asset_db.is_active is True
        sub_db = db.query(Subdomain).filter(Subdomain.asset_id == asset_db.id).first()
        assert sub_db.is_resolving is True


