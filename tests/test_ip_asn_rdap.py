"""Comprehensive test suite for Stage 4: IP / ASN / RDAP Intelligence and Security Remediations."""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
import dns.resolver
import dns.exception
import httpx
from sqlalchemy import inspect, select

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, IPAddress, ASN, IPObservation
from backend.app.models.evidence import Evidence
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.ip_service import IPService, is_public_ip, validate_and_normalize_ip
from backend.app.services.asn_service import ASNService, ASNInfo, CymruDNSASNProvider
from backend.app.services.rdap_service import RDAPService, RDAPInfo, RDAPBootstrap, ALLOWED_RDAP_HOSTS
from backend.app.api.investigations import get_ip_service, get_asn_service, get_rdap_service
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Helper Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_stage4_test_users():
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


def make_mock_resolver(ip_map: dict):
    """Creates a mock DNS resolver returning specified IPs for hostnames."""
    mock_res = MagicMock()
    def resolve_fn(qname, rtype):
        host = str(qname).rstrip(".").lower()
        if host in ip_map:
            ips = ip_map[host]
            answers = []
            for ip in ips:
                rdata = MagicMock()
                rdata.__str__ = MagicMock(return_value=ip)
                answers.append(rdata)
            return answers
        raise dns.resolver.NXDOMAIN()
    mock_res.resolve.side_effect = resolve_fn
    return mock_res


# =====================================================================
# 1. IP SERVICE UNIT TESTS (NORMALIZATION & CLASSIFICATION)
# =====================================================================

def test_ip_service_ipv4_validation_and_normalization():
    """Verify normalization of IPv4 addresses."""
    assert IPService.normalize_ip("8.8.8.8") == "8.8.8.8"
    assert IPService.normalize_ip("  1.1.1.1  ") == "1.1.1.1"
    assert IPService.get_ip_version("8.8.8.8") == 4
    assert IPService.is_valid_ip("8.8.8.8") is True


def test_ip_service_ipv6_validation_and_normalization():
    """Verify normalization and compression of IPv6 addresses."""
    assert IPService.normalize_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    expanded = "2001:4860:4860:0000:0000:0000:0000:8888"
    assert IPService.normalize_ip(expanded) == "2001:4860:4860::8888"
    assert IPService.get_ip_version(expanded) == 6
    assert IPService.is_valid_ip(expanded) is True


def test_ip_service_invalid_ips_rejected():
    """Verify that invalid strings, out-of-range octets, and domain names are rejected."""
    invalid_cases = [
        "999.999.999.999",
        "256.1.1.1",
        "1.2.3.4.5",
        "example.com",
        "subdomain.target.org",
        "",
        "   ",
        "invalid:ipv6:address",
    ]
    for case in invalid_cases:
        assert IPService.normalize_ip(case) is None
        assert IPService.is_valid_ip(case) is False
        assert IPService.get_ip_version(case) is None


def test_ip_service_public_vs_private_classification():
    """Verify accurate classification of public vs private/loopback/link-local/reserved addresses."""
    # Public IPs
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("2606:4700:4700::1111") is True

    # Loopback
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("127.0.0.2") is False
    assert is_public_ip("::1") is False

    # Private IPv4 (RFC 1918)
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("172.31.255.254") is False
    assert is_public_ip("192.168.1.1") is False

    # Link-Local (RFC 3927 & IPv6 fe80::/10)
    assert is_public_ip("169.254.169.254") is False
    assert is_public_ip("fe80::1") is False

    # Unique Local IPv6 (fc00::/7)
    assert is_public_ip("fc00::1") is False
    assert is_public_ip("fd12:3456:789a::1") is False

    # Multicast & Reserved
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("240.0.0.1") is False
    assert is_public_ip("ff02::1") is False
    assert is_public_ip("0.0.0.0") is False
    assert is_public_ip("::") is False


def test_ip_service_extract_unique_ips_from_records():
    """Verify deduplication and extraction of unique IP addresses from DNSRecord observations."""
    subdomain_1 = uuid.uuid4()
    subdomain_2 = uuid.uuid4()

    records = [
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_1, record_type="A", value="93.184.216.34"),
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_2, record_type="A", value="93.184.216.34"),
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_1, record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946"),
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_1, record_type="A", value="10.0.0.5"),
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_1, record_type="CNAME", value="target.cdn.cloudflare.net"),
        DNSRecord(id=uuid.uuid4(), subdomain_id=subdomain_1, record_type="MX", value="10 mail.example.com"),
    ]

    unique = IPService.extract_unique_ips_from_records(records)
    assert len(unique) == 3

    ip_map = {item["ip_address"]: item for item in unique}
    assert "93.184.216.34" in ip_map
    assert ip_map["93.184.216.34"]["ip_version"] == 4
    assert ip_map["93.184.216.34"]["is_public"] is True
    assert set(ip_map["93.184.216.34"]["subdomain_ids"]) == {subdomain_1, subdomain_2}

    assert "2606:2800:220:1:248:1893:25c8:1946" in ip_map
    assert ip_map["2606:2800:220:1:248:1893:25c8:1946"]["ip_version"] == 6
    assert ip_map["2606:2800:220:1:248:1893:25c8:1946"]["is_public"] is True

    assert "10.0.0.5" in ip_map
    assert ip_map["10.0.0.5"]["is_public"] is False


# =====================================================================
# 2. ASN SERVICE UNIT TESTS (MOCKED)
# =====================================================================

def test_asn_service_cymru_ipv4_lookup_success():
    """Verify successful ASN lookup for IPv4 via mocked Team Cymru DNS TXT queries."""
    mock_resolver = MagicMock()

    mock_rdata_origin = MagicMock()
    mock_rdata_origin.strings = [b"15169 | 8.8.8.0/24 | US | arin | 2000-01-01"]

    mock_rdata_asname = MagicMock()
    mock_rdata_asname.strings = [b"15169 | US | arin | 2000-01-01 | GOOGLE, US"]

    def resolve_side_effect(qname, rtype):
        if "origin.asn.cymru.com" in qname:
            mock_ans = MagicMock()
            mock_ans.__iter__.return_value = [mock_rdata_origin]
            return mock_ans
        elif "asn.cymru.com" in qname:
            mock_ans = MagicMock()
            mock_ans.__iter__.return_value = [mock_rdata_asname]
            return mock_ans
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve.side_effect = resolve_side_effect

    provider = CymruDNSASNProvider()
    with patch.object(provider, "_get_resolver", return_value=mock_resolver):
        service = ASNService(provider=provider)
        info = service.lookup("8.8.8.8")

        assert info is not None
        assert info.asn_number == 15169
        assert info.name == "GOOGLE, US"
        assert info.country == "US"
        assert info.allocated_prefix == "8.8.8.0/24"
        assert info.registry == "arin"


def test_asn_service_cymru_ipv6_lookup_success():
    """Verify successful ASN lookup for IPv6 via mocked Team Cymru DNS TXT queries."""
    mock_resolver = MagicMock()

    mock_rdata_origin = MagicMock()
    mock_rdata_origin.strings = [b"15169 | 2001:4860::/32 | US | arin | 2005-03-14"]

    mock_rdata_asname = MagicMock()
    mock_rdata_asname.strings = [b"15169 | US | arin | 2005-03-14 | GOOGLE, US"]

    def resolve_side_effect(qname, rtype):
        if "origin6.asn.cymru.com" in qname:
            mock_ans = MagicMock()
            mock_ans.__iter__.return_value = [mock_rdata_origin]
            return mock_ans
        elif "asn.cymru.com" in qname:
            mock_ans = MagicMock()
            mock_ans.__iter__.return_value = [mock_rdata_asname]
            return mock_ans
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve.side_effect = resolve_side_effect

    provider = CymruDNSASNProvider()
    with patch.object(provider, "_get_resolver", return_value=mock_resolver):
        service = ASNService(provider=provider)
        info = service.lookup("2001:4860:4860::8888")

        assert info is not None
        assert info.asn_number == 15169
        assert info.name == "GOOGLE, US"
        assert info.allocated_prefix == "2001:4860::/32"


def test_asn_service_nxdomain_and_timeout():
    """Verify that NXDOMAIN, NoAnswer, and Timeout exceptions return None gracefully."""
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

    provider = CymruDNSASNProvider()
    with patch.object(provider, "_get_resolver", return_value=mock_resolver):
        service = ASNService(provider=provider)
        assert service.lookup("93.184.216.34") is None

    mock_resolver.resolve.side_effect = dns.exception.Timeout()
    with patch.object(provider, "_get_resolver", return_value=mock_resolver):
        service = ASNService(provider=provider)
        assert service.lookup("93.184.216.34") is None


def test_asn_service_skips_private_ips():
    """Verify that ASN lookups for private / loopback IPs are skipped without DNS queries."""
    mock_provider = MagicMock()
    service = ASNService(provider=mock_provider)

    assert service.lookup("127.0.0.1") is None
    assert service.lookup("10.0.0.1") is None
    assert service.lookup("192.168.1.1") is None
    assert service.lookup("::1") is None
    mock_provider.lookup.assert_not_called()


# =====================================================================
# 3. ISSUE 2: RDAP BOOTSTRAP DISCOVERY TESTS
# =====================================================================

def test_rdap_bootstrap_ipv4_mapping():
    """Verify IPv4 prefix to RIR mapping across all 5 Regional Internet Registries."""
    bootstrap = RDAPBootstrap()

    # ARIN (e.g. 8.8.8.8, 93.184.216.34)
    assert bootstrap.get_authoritative_base_url("8.8.8.8") == "https://rdap.arin.net/registry/"
    assert bootstrap.build_ip_url("8.8.8.8") == "https://rdap.arin.net/registry/ip/8.8.8.8"

    # RIPE NCC (e.g. 193.0.0.1, 2.16.0.1)
    assert bootstrap.get_authoritative_base_url("193.0.0.1") == "https://rdap.db.ripe.net/"
    assert bootstrap.build_ip_url("193.0.0.1") == "https://rdap.db.ripe.net/ip/193.0.0.1"

    # APNIC (e.g. 1.1.1.1, 202.12.27.33)
    assert bootstrap.get_authoritative_base_url("1.1.1.1") == "https://rdap.apnic.net/"
    assert bootstrap.build_ip_url("1.1.1.1") == "https://rdap.apnic.net/ip/1.1.1.1"

    # LACNIC (e.g. 200.1.2.3, 177.0.0.1)
    assert bootstrap.get_authoritative_base_url("200.1.2.3") == "https://rdap.lacnic.net/rdap/"
    assert bootstrap.build_ip_url("200.1.2.3") == "https://rdap.lacnic.net/rdap/ip/200.1.2.3"

    # AFRINIC (e.g. 196.216.2.1, 41.0.0.1)
    assert bootstrap.get_authoritative_base_url("41.0.0.1") == "https://rdap.afrinic.net/rdap/"
    assert bootstrap.build_ip_url("41.0.0.1") == "https://rdap.afrinic.net/rdap/ip/41.0.0.1"


def test_rdap_bootstrap_ipv6_mapping():
    """Verify IPv6 prefix to RIR mapping across all 5 RIRs."""
    bootstrap = RDAPBootstrap()

    # ARIN (e.g. 2606:4700::1, 2600::1)
    assert bootstrap.get_authoritative_base_url("2606:4700::1") == "https://rdap.arin.net/registry/"
    assert bootstrap.build_ip_url("2606:4700::1") == "https://rdap.arin.net/registry/ip/2606:4700::1"

    # RIPE NCC (e.g. 2a00:1450:4001::)
    assert bootstrap.get_authoritative_base_url("2a00:1450:4001::") == "https://rdap.db.ripe.net/"

    # APNIC (e.g. 2400:cb00::1)
    assert bootstrap.get_authoritative_base_url("2400:cb00::1") == "https://rdap.apnic.net/"

    # LACNIC (e.g. 2800::1)
    assert bootstrap.get_authoritative_base_url("2800::1") == "https://rdap.lacnic.net/rdap/"

    # AFRINIC (e.g. 2c00::1)
    assert bootstrap.get_authoritative_base_url("2c00::1") == "https://rdap.afrinic.net/rdap/"


def test_rdap_bootstrap_custom_registry_loading():
    """Verify dynamic loading of standard RFC 7484 / IANA bootstrap JSON format."""
    bootstrap = RDAPBootstrap()
    custom_ipv4_data = {
        "version": "1.0",
        "services": [
            [["198.51.100.0/24"], ["https://rdap.arin.net/registry/"]],
            [["203.0.113.0/24"], ["https://rdap.apnic.net/"]],
        ]
    }
    loaded = bootstrap.load_bootstrap_registry(custom_ipv4_data, ip_version=4)
    assert loaded is True
    assert bootstrap.get_authoritative_base_url("198.51.100.1") == "https://rdap.arin.net/registry/"
    assert bootstrap.get_authoritative_base_url("203.0.113.1") == "https://rdap.apnic.net/"


def test_rdap_bootstrap_no_matching_entry_and_failure():
    """Verify graceful handling when an IP does not match any known bootstrap prefix or on invalid input."""
    bootstrap = RDAPBootstrap()
    # Empty registry simulation
    bootstrap.load_bootstrap_registry({"services": []}, ip_version=4)
    assert bootstrap.get_authoritative_base_url("8.8.8.8") is None
    assert bootstrap.build_ip_url("8.8.8.8") is None

    # Invalid input
    assert bootstrap.get_authoritative_base_url("invalid-ip") is None
    assert bootstrap.build_ip_url("") is None


# =====================================================================
# 4. ISSUE 3: RDAP REDIRECT SSRF HARDENING & PRE-CONNECTION DNS TESTS
# =====================================================================

def test_rdap_service_approved_public_rdap_hostname_works():
    """Verify that an approved RDAP host that resolves to public IPs is permitted and queried."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = json.dumps({"name": "GOGL", "handle": "NET-8-8-8-0-1", "country": "US"})
    mock_resp.content = mock_resp.text.encode("utf-8")
    mock_client.get.return_value = mock_resp

    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["192.0.47.8"],
    })

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    info = service.lookup("8.8.8.8")

    assert info is not None
    assert info.network_name == "GOGL"
    assert mock_client.get.call_count == 1


def test_rdap_service_approved_hostname_resolving_to_private_ip_is_blocked():
    """Verify that an approved RDAP hostname (e.g. rdap.arin.net) is BLOCKED if it resolves to private IP."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["10.0.0.1"],  # RFC 1918 Private IP
    })

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    assert service.lookup("8.8.8.8") is None
    mock_client.get.assert_not_called()


def test_rdap_service_approved_hostname_resolving_to_loopback_is_blocked():
    """Verify that an approved RDAP hostname is BLOCKED if it resolves to 127.0.0.1 or ::1."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["127.0.0.1"],
    })

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    assert service.lookup("8.8.8.8") is None
    mock_client.get.assert_not_called()


def test_rdap_service_approved_hostname_resolving_to_link_local_is_blocked():
    """Verify that an approved RDAP hostname is BLOCKED if it resolves to 169.254.169.254 (cloud metadata)."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["169.254.169.254"],
    })

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    assert service.lookup("8.8.8.8") is None
    mock_client.get.assert_not_called()


def test_rdap_service_redirect_to_unapproved_hostname_blocked():
    """Verify that redirects to unapproved external or internal hostnames are blocked."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["192.0.47.8"],
    })

    # 302 redirect to unapproved hostname
    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"Location": "https://evil.attacker.local/rdap/ip/8.8.8.8"}
    mock_client.get.return_value = resp_redirect

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    assert service.lookup("8.8.8.8") is None
    assert mock_client.get.call_count == 1  # Blocked before requesting hop


def test_rdap_service_redirect_to_approved_hostname_with_private_ip_blocked():
    """Verify that a redirect to an approved hostname (rdap.db.ripe.net) that resolves to private IP is blocked."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["192.0.47.8"],         # Initial host is public
        "rdap.db.ripe.net": ["192.168.1.50"],    # Redirect destination resolves to private IP
    })

    resp_redirect = MagicMock()
    resp_redirect.status_code = 302
    resp_redirect.headers = {"Location": "https://rdap.db.ripe.net/ip/8.8.8.8"}
    mock_client.get.return_value = resp_redirect

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    assert service.lookup("8.8.8.8") is None
    assert mock_client.get.call_count == 1


def test_rdap_service_multi_hop_redirect_validates_every_hop():
    """Verify that multi-hop redirects (Hop 1 -> Hop 2 -> Final) validate DNS and allowlist at each hop."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["192.0.47.8"],
        "rdap.apnic.net": ["203.119.102.40"],
        "rdap.db.ripe.net": ["193.0.0.135"],
    })

    resp_hop1 = MagicMock()
    resp_hop1.status_code = 302
    resp_hop1.headers = {"Location": "https://rdap.apnic.net/ip/193.0.0.1"}

    resp_hop2 = MagicMock()
    resp_hop2.status_code = 302
    resp_hop2.headers = {"Location": "https://rdap.db.ripe.net/ip/193.0.0.1"}

    resp_final = MagicMock()
    resp_final.status_code = 200
    sample_ripe_json = {"name": "RIPE-NCC", "handle": "193.0.0.0 - 193.0.7.255", "country": "NL"}
    resp_final.text = json.dumps(sample_ripe_json)
    resp_final.content = json.dumps(sample_ripe_json).encode("utf-8")

    mock_client.get.side_effect = [resp_hop1, resp_hop2, resp_final]

    service = RDAPService(client=mock_client, resolver=mock_resolver)
    # 193.0.0.1 bootstraps to RIPE; we can test multi-hop by requesting through service
    info = service.lookup("193.0.0.1")

    assert info is not None
    assert info.network_name == "RIPE-NCC"
    assert info.country == "NL"


def test_rdap_service_redirect_limit_enforced():
    """Verify that exceeding the max redirect limit returns None without looping indefinitely."""
    mock_client = MagicMock()
    mock_resolver = make_mock_resolver({
        "rdap.arin.net": ["192.0.47.8"],
        "rdap.db.ripe.net": ["193.0.0.135"],
    })

    # Infinite 302 loop between two approved hosts
    resp_loop1 = MagicMock()
    resp_loop1.status_code = 302
    resp_loop1.headers = {"Location": "https://rdap.db.ripe.net/ip/8.8.8.8"}

    resp_loop2 = MagicMock()
    resp_loop2.status_code = 302
    resp_loop2.headers = {"Location": "https://rdap.arin.net/registry/ip/8.8.8.8"}

    mock_client.get.side_effect = [resp_loop1, resp_loop2, resp_loop1, resp_loop2, resp_loop1]

    service = RDAPService(client=mock_client, resolver=mock_resolver, max_redirects=3)
    assert service.lookup("8.8.8.8") is None
    assert mock_client.get.call_count <= 4


# =====================================================================
# 5. ISSUE 1: HISTORICAL IP/ASN SCAN ISOLATION & IPOBSERVATION TESTS
# =====================================================================

def test_alembic_migration_creates_ip_observations_table():
    """Verify that the database migration created the ip_observations table with expected columns and constraints."""
    with TestingSessionLocal() as db:
        inspector = inspect(db.bind)
        tables = inspector.get_table_names()
        assert "ip_observations" in tables

        columns = {c["name"]: c for c in inspector.get_columns("ip_observations")}
        assert "id" in columns
        assert "scan_run_id" in columns
        assert "ip_address_id" in columns
        assert "asn_id" in columns
        assert "observed_at" in columns

        fks = inspector.get_foreign_keys("ip_observations")
        fk_tables = [fk["referred_table"] for fk in fks]
        assert "scan_runs" in fk_tables
        assert "ip_addresses" in fk_tables
        assert "asns" in fk_tables


def test_ip_observation_created_with_correct_fields_and_relationships():
    """Verify that IPObservation is created for enriched IP and correctly references scan_run_id, ip_address_id, asn_id."""
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="Obs Corp", primary_domain="obs.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="IP Observation Relationship Test",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        asset = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="web.obs.example.com", source="test")
        db.add(asset)
        db.flush()

        domain = Domain(asset_id=asset.id, domain_name="obs.example.com")
        db.add(domain)
        db.flush()

        sub = Subdomain(asset_id=asset.id, domain_id=domain.id, subdomain_name="web.obs.example.com", is_resolving=True)
        db.add(sub)
        db.flush()

        dns_rec = DNSRecord(subdomain_id=sub.id, record_type="A", value="8.8.8.8")
        db.add(dns_rec)
        db.commit()

        inv_id = str(investigation.id)

    mock_asn = MagicMock(spec=ASNService)
    mock_asn.lookup.return_value = ASNInfo(asn_number=15169, name="GOOGLE", country="US", allocated_prefix="8.8.8.0/24")

    mock_rdap = MagicMock(spec=RDAPService)
    mock_rdap.lookup.return_value = RDAPInfo(ip="8.8.8.8", network_name="GOGL", country="US", raw_json_str='{"name": "GOGL"}')

    app.dependency_overrides[get_asn_service] = lambda: mock_asn
    app.dependency_overrides[get_rdap_service] = lambda: mock_rdap

    try:
        res = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert res.status_code == 200
        scan_run_id = uuid.UUID(res.json()["scan_run_id"])

        with TestingSessionLocal() as db:
            # Verify IPAddress entity
            ip_addr = db.query(IPAddress).filter(IPAddress.ip_address == "8.8.8.8").first()
            assert ip_addr is not None

            # Verify ASN entity
            asn_db = db.query(ASN).filter(ASN.asn_number == 15169).first()
            assert asn_db is not None

            # Verify IPObservation
            obs = db.query(IPObservation).filter(
                IPObservation.scan_run_id == scan_run_id,
                IPObservation.ip_address_id == ip_addr.id,
            ).first()

            assert obs is not None
            assert obs.scan_run_id == scan_run_id
            assert obs.ip_address_id == ip_addr.id
            assert obs.asn_id == asn_db.id
            assert obs.observed_at is not None

            # Verify relationships
            assert obs in ip_addr.observations
            assert obs in asn_db.ip_observations

    finally:
        app.dependency_overrides.pop(get_asn_service, None)
        app.dependency_overrides.pop(get_rdap_service, None)


def test_historical_scan_isolation_same_ip_different_asns():
    """
    Verify the fundamental requirement:
    Scan A: 1.2.3.4 -> ASN 100
    Scan B: 1.2.3.4 -> ASN 200
    
    Both observations remain queryable and Scan A historical record is NEVER overwritten.
    """
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="BGP Shift Corp", primary_domain="bgpshift.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="Historical BGP ASN Shift Test",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        asset = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="host.bgpshift.example.com", source="test")
        db.add(asset)
        db.flush()

        domain = Domain(asset_id=asset.id, domain_name="bgpshift.example.com")
        db.add(domain)
        db.flush()

        sub = Subdomain(asset_id=asset.id, domain_id=domain.id, subdomain_name="host.bgpshift.example.com", is_resolving=True)
        db.add(sub)
        db.flush()

        dns_rec = DNSRecord(subdomain_id=sub.id, record_type="A", value="1.2.3.4")
        db.add(dns_rec)
        db.commit()

        inv_id = str(investigation.id)

    mock_asn = MagicMock(spec=ASNService)
    mock_rdap = MagicMock(spec=RDAPService)
    mock_rdap.lookup.return_value = RDAPInfo(ip="1.2.3.4", network_name="APNIC-NET", raw_json_str='{"name": "APNIC-NET"}')

    app.dependency_overrides[get_asn_service] = lambda: mock_asn
    app.dependency_overrides[get_rdap_service] = lambda: mock_rdap

    try:
        # --- SCAN A: 1.2.3.4 -> ASN 100 ---
        mock_asn.lookup.return_value = ASNInfo(asn_number=100, name="AS100-OLD-ISP", country="US")
        res_a = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert res_a.status_code == 200
        scan_run_a_id = uuid.UUID(res_a.json()["scan_run_id"])

        # --- SCAN B: 1.2.3.4 -> ASN 200 ---
        mock_asn.lookup.return_value = ASNInfo(asn_number=200, name="AS200-NEW-ISP", country="US")
        res_b = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert res_b.status_code == 200
        scan_run_b_id = uuid.UUID(res_b.json()["scan_run_id"])

        assert scan_run_a_id != scan_run_b_id

        # --- VERIFY DATABASE STATE ---
        with TestingSessionLocal() as db:
            # 1. IPAddress entity is reused and stores current ASN (200)
            ip_addr = db.query(IPAddress).filter(IPAddress.ip_address == "1.2.3.4").one()
            asn_100 = db.query(ASN).filter(ASN.asn_number == 100).one()
            asn_200 = db.query(ASN).filter(ASN.asn_number == 200).one()

            assert ip_addr.asn_id == asn_200.id

            # 2. Both IPObservations exist and are distinct
            obs_a = db.query(IPObservation).filter(
                IPObservation.scan_run_id == scan_run_a_id,
                IPObservation.ip_address_id == ip_addr.id,
            ).one()

            obs_b = db.query(IPObservation).filter(
                IPObservation.scan_run_id == scan_run_b_id,
                IPObservation.ip_address_id == ip_addr.id,
            ).one()

            # Scan A observation MUST STILL POINT TO ASN 100!
            assert obs_a.asn_id == asn_100.id
            # Scan B observation points to ASN 200!
            assert obs_b.asn_id == asn_200.id

            # IPAddress has exactly 2 observations
            assert len(ip_addr.observations) == 2

        # --- VERIFY API OBSERVATION QUERY ENDPOINT ---
        obs_res = client.get(f"/api/investigations/{inv_id}/ip-observations", headers=analyst_headers)
        assert obs_res.status_code == 200
        obs_data = obs_res.json()
        assert len(obs_data) == 2

        obs_map = {item["scan_run_id"]: item for item in obs_data}
        assert obs_map[str(scan_run_a_id)]["asn_number"] == 100
        assert obs_map[str(scan_run_a_id)]["asn_name"] == "AS100-OLD-ISP"
        assert obs_map[str(scan_run_b_id)]["asn_number"] == 200
        assert obs_map[str(scan_run_b_id)]["asn_name"] == "AS200-NEW-ISP"

        # Filter by scan_run_id
        res_filter_a = client.get(
            f"/api/investigations/{inv_id}/ip-observations?scan_run_id={scan_run_a_id}",
            headers=analyst_headers,
        )
        assert res_filter_a.status_code == 200
        assert len(res_filter_a.json()) == 1
        assert res_filter_a.json()[0]["asn_number"] == 100

    finally:
        app.dependency_overrides.pop(get_asn_service, None)
        app.dependency_overrides.pop(get_rdap_service, None)


def test_ip_observation_deduplication_within_single_scan():
    """Verify that multiple DNS records with the same IP in one scan do not create duplicate IPObservations."""
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="Dedup Corp", primary_domain="dedup.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="IP Observation Dedup Test",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        asset_1 = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="a.dedup.example.com", source="test")
        asset_2 = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="b.dedup.example.com", source="test")
        db.add_all([asset_1, asset_2])
        db.flush()

        domain = Domain(asset_id=asset_1.id, domain_name="dedup.example.com")
        db.add(domain)
        db.flush()

        sub_1 = Subdomain(asset_id=asset_1.id, domain_id=domain.id, subdomain_name="a.dedup.example.com", is_resolving=True)
        sub_2 = Subdomain(asset_id=asset_2.id, domain_id=domain.id, subdomain_name="b.dedup.example.com", is_resolving=True)
        db.add_all([sub_1, sub_2])
        db.flush()

        # Both subdomains resolve to the same IP 93.184.216.34
        dns_1 = DNSRecord(subdomain_id=sub_1.id, record_type="A", value="93.184.216.34")
        dns_2 = DNSRecord(subdomain_id=sub_2.id, record_type="A", value="93.184.216.34")
        db.add_all([dns_1, dns_2])
        db.commit()

        inv_id = str(investigation.id)

    mock_asn = MagicMock(spec=ASNService)
    mock_asn.lookup.return_value = ASNInfo(asn_number=15133, name="EDGECAST", country="US")
    mock_rdap = MagicMock(spec=RDAPService)
    mock_rdap.lookup.return_value = RDAPInfo(ip="93.184.216.34", network_name="EDGECAST-NET")

    app.dependency_overrides[get_asn_service] = lambda: mock_asn
    app.dependency_overrides[get_rdap_service] = lambda: mock_rdap

    try:
        res = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert res.status_code == 200
        scan_id = uuid.UUID(res.json()["scan_run_id"])

        with TestingSessionLocal() as db:
            observations = db.query(IPObservation).filter(IPObservation.scan_run_id == scan_id).all()
            # Must be exactly 1 observation despite multiple DNS records
            assert len(observations) == 1

    finally:
        app.dependency_overrides.pop(get_asn_service, None)
        app.dependency_overrides.pop(get_rdap_service, None)


# =====================================================================
# 6. INTEGRATION WORKFLOW & DB PERSISTENCE
# =====================================================================

def test_full_investigation_ip_enrichment_workflow():
    """
    Verify complete Stage 4 flow:
    1. Create Target, Investigation, Subdomain, and DNS A/AAAA records.
    2. Execute POST /api/investigations/{id}/enrich/ip with mocked ASN/RDAP.
    3. Verify response metrics, ScanRun, Asset (type=ip), ASN, IPAddress, IPObservation, and Evidence.
    """
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="Enrichment Corp", primary_domain="enrichment.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="IP Intelligence Test Assessment",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        root_asset = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="domain", value="enrichment.example.com", source="test")
        db.add(root_asset)
        db.flush()

        domain = Domain(asset_id=root_asset.id, domain_name="enrichment.example.com")
        db.add(domain)
        db.flush()

        sub_asset_1 = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="api.enrichment.example.com", source="test")
        db.add(sub_asset_1)
        db.flush()

        subdomain_1 = Subdomain(asset_id=sub_asset_1.id, domain_id=domain.id, subdomain_name="api.enrichment.example.com", is_resolving=True)
        db.add(subdomain_1)
        db.flush()

        dns_rec_1 = DNSRecord(subdomain_id=subdomain_1.id, record_type="A", value="93.184.216.34", ttl=300)
        db.add(dns_rec_1)

        sub_asset_2 = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="cdn.enrichment.example.com", source="test")
        db.add(sub_asset_2)
        db.flush()

        subdomain_2 = Subdomain(asset_id=sub_asset_2.id, domain_id=domain.id, subdomain_name="cdn.enrichment.example.com", is_resolving=True)
        db.add(subdomain_2)
        db.flush()

        dns_rec_2 = DNSRecord(subdomain_id=subdomain_2.id, record_type="A", value="93.184.216.34", ttl=300)
        dns_rec_3 = DNSRecord(subdomain_id=subdomain_2.id, record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946", ttl=300)
        dns_rec_4 = DNSRecord(subdomain_id=subdomain_2.id, record_type="A", value="10.0.0.99", ttl=300)
        db.add_all([dns_rec_2, dns_rec_3, dns_rec_4])
        db.commit()

        inv_id = str(investigation.id)

    mock_asn = MagicMock(spec=ASNService)
    def mock_asn_lookup(ip):
        if ip == "93.184.216.34":
            return ASNInfo(asn_number=15133, name="EDGECAST", country="US", allocated_prefix="93.184.216.0/24")
        elif ip == "2606:2800:220:1:248:1893:25c8:1946":
            return ASNInfo(asn_number=15133, name="EDGECAST", country="US", allocated_prefix="2606:2800::/32")
        return None
    mock_asn.lookup.side_effect = mock_asn_lookup

    mock_rdap = MagicMock(spec=RDAPService)
    def mock_rdap_lookup(ip):
        if ip == "93.184.216.34":
            return RDAPInfo(
                ip="93.184.216.34",
                network_name="EDGECAST-NET",
                handle="NET-93-184-216-0-1",
                start_address="93.184.216.0",
                end_address="93.184.216.255",
                cidr="93.184.216.0/24",
                country="US",
                organization="EdgeCast Networks, Inc.",
                status=["active"],
                raw_data={"name": "EDGECAST-NET"},
                raw_json_str='{"name": "EDGECAST-NET", "handle": "NET-93-184-216-0-1"}',
            )
        return None
    mock_rdap.lookup.side_effect = mock_rdap_lookup

    app.dependency_overrides[get_asn_service] = lambda: mock_asn
    app.dependency_overrides[get_rdap_service] = lambda: mock_rdap

    try:
        response = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert response.status_code == 200
        data = response.json()

        assert data["investigation_id"] == inv_id
        assert data["target_domain"] == "enrichment.example.com"
        assert data["ips_processed"] == 3
        assert data["public_ips"] == 2
        assert data["skipped_non_public"] == 1
        assert data["asn_success"] == 2
        assert data["rdap_success"] == 1

        with TestingSessionLocal() as db:
            scan_run = db.get(ScanRun, uuid.UUID(data["scan_run_id"]))
            assert scan_run is not None
            assert scan_run.status == "completed"

            asn_db = db.query(ASN).filter(ASN.asn_number == 15133).first()
            assert asn_db is not None
            assert asn_db.name == "EDGECAST"

            ip_records = db.query(IPAddress).all()
            ip_strs = [r.ip_address for r in ip_records]
            assert "93.184.216.34" in ip_strs
            assert "2606:2800:220:1:248:1893:25c8:1946" in ip_strs

            # Check IPObservations created
            observations = db.query(IPObservation).filter(IPObservation.scan_run_id == scan_run.id).all()
            assert len(observations) == 2

            # Check Evidence
            evidence_rec = db.query(Evidence).filter(
                Evidence.investigation_id == uuid.UUID(inv_id),
                Evidence.evidence_type == "rdap"
            ).first()
            assert evidence_rec is not None
            assert evidence_rec.verify_hash() is True

    finally:
        app.dependency_overrides.pop(get_asn_service, None)
        app.dependency_overrides.pop(get_rdap_service, None)


def test_query_endpoints_ip_addresses_and_asns():
    """Verify authenticated query endpoints for IP addresses and ASNs."""
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="Query Corp", primary_domain="query.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="Query Endpoints Test",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        asn = db.query(ASN).filter(ASN.asn_number == 15169).first()
        if not asn:
            asn = ASN(asn_number=15169, name="GOOGLE", country="US", allocated_prefix="8.8.8.0/24")
            db.add(asn)
            db.flush()

        ip_asset = Asset(
            target_id=target.id,
            investigation_id=investigation.id,
            asset_type="ip",
            value="8.8.8.8",
            source="dns_enriched",
        )
        db.add(ip_asset)
        db.flush()

        ip_addr = db.query(IPAddress).filter(IPAddress.ip_address == "8.8.8.8").first()
        if not ip_addr:
            ip_addr = IPAddress(
                asset_id=ip_asset.id,
                ip_address="8.8.8.8",
                ip_version=4,
                asn_id=asn.id,
                country="US",
                organization="Google LLC",
                is_active=True,
            )
            db.add(ip_addr)
        else:
            ip_addr.asset_id = ip_asset.id
            ip_addr.asn_id = asn.id
            ip_addr.organization = "Google LLC"
        db.commit()

        inv_id = str(investigation.id)

    # 1. GET /api/investigations/{id}/ip-addresses
    res_ips = client.get(f"/api/investigations/{inv_id}/ip-addresses", headers=analyst_headers)
    assert res_ips.status_code == 200
    ips_data = res_ips.json()
    assert len(ips_data) == 1
    assert ips_data[0]["ip_address"] == "8.8.8.8"
    assert ips_data[0]["asn"]["asn_number"] == 15169
    assert ips_data[0]["organization"] == "Google LLC"

    # 2. GET /api/investigations/{id}/asns
    res_asns = client.get(f"/api/investigations/{inv_id}/asns", headers=analyst_headers)
    assert res_asns.status_code == 200
    asns_data = res_asns.json()
    assert len(asns_data) == 1
    assert asns_data[0]["asn_number"] == 15169
    assert asns_data[0]["name"] == "GOOGLE"
    assert asns_data[0]["ip_count"] == 1


def test_enrich_investigation_partial_failures_fault_tolerant():
    """Verify that if one IP lookup fails (timeout/error), remaining IPs are enriched and run succeeds."""
    analyst_headers = get_auth_headers("analyst_one")

    with TestingSessionLocal() as db:
        user = db.query(User).filter(User.username == "analyst_one").first()

        target = Target(name="Fault Corp", primary_domain="fault.example.com", is_authorized=True)
        db.add(target)
        db.flush()

        investigation = Investigation(
            reference_code=f"INV-TEST-{uuid.uuid4().hex[:6].upper()}",
            target_id=target.id,
            title="Fault Tolerance Test",
            status="active",
            created_by_id=user.id,
        )
        db.add(investigation)
        db.flush()

        sub_asset = Asset(target_id=target.id, investigation_id=investigation.id, asset_type="subdomain", value="s.fault.example.com", source="test")
        db.add(sub_asset)
        db.flush()

        domain = Domain(asset_id=sub_asset.id, domain_name="fault.example.com")
        db.add(domain)
        db.flush()

        sub = Subdomain(asset_id=sub_asset.id, domain_id=domain.id, subdomain_name="s.fault.example.com", is_resolving=True)
        db.add(sub)
        db.flush()

        dns_1 = DNSRecord(subdomain_id=sub.id, record_type="A", value="8.8.8.8")
        dns_2 = DNSRecord(subdomain_id=sub.id, record_type="A", value="104.16.123.96")
        db.add_all([dns_1, dns_2])
        db.commit()

        inv_id = str(investigation.id)

    mock_asn = MagicMock(spec=ASNService)
    def mock_asn_call(ip):
        if ip == "8.8.8.8":
            return ASNInfo(asn_number=15169, name="GOOGLE", country="US")
        return None
    mock_asn.lookup.side_effect = mock_asn_call

    mock_rdap = MagicMock(spec=RDAPService)
    def mock_rdap_call(ip):
        if ip == "8.8.8.8":
            return RDAPInfo(ip="8.8.8.8", network_name="GOGL")
        return None
    mock_rdap.lookup.side_effect = mock_rdap_call

    app.dependency_overrides[get_asn_service] = lambda: mock_asn
    app.dependency_overrides[get_rdap_service] = lambda: mock_rdap

    try:
        res = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()

        assert data["ips_processed"] == 2
        assert data["public_ips"] == 2
        assert data["asn_success"] == 1
        assert data["rdap_success"] == 1
        assert data["failed"] == 1

        assert len(data["results"]) == 2
        status_by_ip = {r["ip_address"]: r["status"] for r in data["results"]}
        assert status_by_ip["8.8.8.8"] == "enriched"
        assert status_by_ip["104.16.123.96"] == "failed"

    finally:
        app.dependency_overrides.pop(get_asn_service, None)
        app.dependency_overrides.pop(get_rdap_service, None)


# =====================================================================
# 7. RBAC & ACCESS CONTROL TESTS
# =====================================================================

def test_enrich_investigation_authentication_required():
    """Verify that unauthenticated requests to IP enrichment are rejected with 401."""
    fake_id = str(uuid.uuid4())
    res = client.post(f"/api/investigations/{fake_id}/enrich/ip")
    assert res.status_code == 401


def test_enrich_investigation_not_found():
    """Verify that a non-existent investigation ID returns 404."""
    analyst_headers = get_auth_headers("analyst_one")
    fake_id = str(uuid.uuid4())
    res = client.post(f"/api/investigations/{fake_id}/enrich/ip", headers=analyst_headers)
    assert res.status_code == 404


def test_enrich_investigation_forbidden_for_other_analyst():
    """Verify that Analyst Two cannot enrich an investigation owned by Analyst One."""
    analyst_one_headers = get_auth_headers("analyst_one")
    analyst_two_headers = get_auth_headers("analyst_two")

    create_res = client.post(
        "/api/investigations",
        json={"name": "Owner Assessment", "target_domain": "owner.example.com"},
        headers=analyst_one_headers,
    )
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    res = client.post(f"/api/investigations/{inv_id}/enrich/ip", headers=analyst_two_headers)
    assert res.status_code == 403
