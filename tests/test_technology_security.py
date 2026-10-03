"""Comprehensive test suite for Stage 5: Technology Fingerprinting & HTTP Security Intelligence."""

import json
import socket
import ssl
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
import httpx
from sqlalchemy import select

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, ServiceExposure
from backend.app.models.technology import Technology
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.http_service import (
    HTTPIntelligenceService,
    HTTPProbeObservation,
    SecurityHeaderAnalysis,
    TLSMetadata,
)
from backend.app.services.technology_service import (
    TechnologyService,
    TechnologyFingerprintProvider,
    DetectedTechnology,
    TechnologySignature,
)
from backend.app.api.investigations import get_http_intelligence_service, get_technology_service
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Helper Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_stage5_test_users():
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
        host_str = str(qname).rstrip(".")
        if host_str in ip_map and rtype in ip_map[host_str]:
            items = ip_map[host_str][rtype]
            if not items:
                import dns.resolver
                raise dns.resolver.NoAnswer()
            mock_answers = []
            for ip in items:
                mock_item = MagicMock()
                mock_item.__str__.return_value = ip
                mock_answers.append(mock_item)
            return mock_answers
        import dns.resolver
        raise dns.resolver.NXDOMAIN()
    mock_res.resolve.side_effect = resolve_fn
    return mock_res


# ==========================================
# 1-6. HTTP INTELLIGENCE & METADATA TESTS
# ==========================================

def test_1_http_metadata_extraction_successful():
    """Test 1: Successful HTTP GET metadata extraction."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("http://example.com")
    mock_resp.http_version = "HTTP/1.1"
    mock_resp.headers = httpx.Headers({
        "server": "nginx/1.24.0",
        "content-type": "text/html; charset=UTF-8",
        "content-length": "120",
        "x-powered-by": "PHP/8.2.10",
    })
    mock_resp.cookies = {"session_id": "abc123xyz"}
    mock_resp.text = "<html><head><title>Example Domain Portal</title></head><body><h1>Hello</h1></body></html>"
    mock_client.get.return_value = mock_resp

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")

    assert obs.is_reachable is True
    assert obs.status_code == 200
    assert obs.http_version == "HTTP/1.1"
    assert obs.server_header == "nginx/1.24.0"
    assert obs.powered_by_header == "PHP/8.2.10"
    assert obs.content_type == "text/html; charset=UTF-8"
    assert obs.page_title == "Example Domain Portal"
    assert obs.cookies == {"session_id": "abc123xyz"}
    assert "Example Domain Portal" in obs.body_snippet


def test_2_https_metadata_extraction_successful():
    """Test 2: Successful HTTPS metadata and TLS extraction."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("https://secure.example.com")
    mock_resp.http_version = "HTTP/2"
    mock_resp.headers = httpx.Headers({
        "server": "cloudflare",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
    })
    mock_resp.cookies = {}
    mock_resp.text = "<html><head><title>Secure Portal</title></head></html>"
    mock_client.get.return_value = mock_resp

    mock_resolver = make_mock_resolver({"secure.example.com": {"A": ["104.21.55.2"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    # Mock TLS inspection
    with patch.object(service, "_inspect_tls", return_value=TLSMetadata(
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_subject="secure.example.com",
        cert_issuer="Let's Encrypt",
        cert_valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
        cert_valid_to=datetime(2024, 4, 1, tzinfo=timezone.utc),
        cert_san_list=["secure.example.com", "*.example.com"],
    )):
        obs = service.probe_service("secure.example.com", 443, protocol="tcp", service_name="https")

    assert obs.is_reachable is True
    assert obs.status_code == 200
    assert obs.service_name == "https"
    assert obs.tls_metadata is not None
    assert obs.tls_metadata.tls_version == "TLSv1.3"
    assert obs.tls_metadata.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert obs.tls_metadata.cert_issuer == "Let's Encrypt"
    assert "secure.example.com" in obs.tls_metadata.cert_san_list


def test_3_redirect_handling_single_and_multi_hop():
    """Test 3: Redirect handling and hop count tracking."""
    mock_client = MagicMock(spec=httpx.Client)

    # 1st request: 301 redirect to https://example.com/app
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 301
    mock_resp1.url = httpx.URL("http://example.com")
    mock_resp1.headers = httpx.Headers({"Location": "https://example.com/app"})
    mock_resp1.cookies = {}
    mock_resp1.text = ""

    # 2nd request: 200 OK
    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.url = httpx.URL("https://example.com/app")
    mock_resp2.headers = httpx.Headers({"server": "nginx"})
    mock_resp2.cookies = {}
    mock_resp2.text = "<html><title>App Landing</title></html>"

    mock_client.get.side_effect = [mock_resp1, mock_resp2]

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")

    assert obs.is_reachable is True
    assert obs.status_code == 200
    assert obs.redirect_count == 1
    assert obs.final_url == "https://example.com/app"
    assert obs.page_title == "App Landing"


def test_4_response_size_bounding():
    """Test 4: Response-size bounding ensures bodies over 64 KB are truncated."""
    mock_client = MagicMock(spec=httpx.Client)
    huge_text = "A" * (HTTPIntelligenceService.MAX_BODY_BYTES + 50000)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("http://example.com")
    mock_resp.headers = httpx.Headers({"server": "Apache"})
    mock_resp.cookies = {}
    mock_resp.text = huge_text
    mock_client.get.return_value = mock_resp

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")

    assert obs.is_reachable is True
    assert len(obs.body_snippet) <= HTTPIntelligenceService.MAX_BODY_BYTES


def test_5_timeout_handling_graceful():
    """Test 5: Timeout exception handling returns unreachable observation without crashing."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.side_effect = httpx.ConnectTimeout("Connection timed out")

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")

    assert obs.is_reachable is False
    assert obs.error == "Connection Timeout"


def test_6_http_error_handling_connection_refused():
    """Test 6: Connection refused and network errors handled gracefully."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.side_effect = httpx.ConnectError("Connection refused by peer")

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")

    assert obs.is_reachable is False
    assert "Connection Refused" in (obs.error or "")


# ==========================================
# 7-14. TECHNOLOGY DETECTION TESTS
# ==========================================

def test_7_nginx_detection_from_server_header():
    """Test 7: Nginx detection with version extraction and CPE generation."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "nginx/1.24.0", "content-type": "text/html"},
    )

    detected = tech_service.fingerprint_http_observation(obs)

    nginx = next((t for t in detected if t.name == "nginx"), None)
    assert nginx is not None
    assert nginx.category == "web_server"
    assert nginx.version == "1.24.0"
    assert nginx.cpe == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert "nginx/1.24.0" in nginx.evidence


def test_8_apache_detection():
    """Test 8: Apache detection with version extraction."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "Apache/2.4.56 (Debian)"},
    )

    detected = tech_service.fingerprint_http_observation(obs)

    apache = next((t for t in detected if t.name == "Apache"), None)
    assert apache is not None
    assert apache.category == "web_server"
    assert apache.version == "2.4.56"
    assert "Apache/2.4.56" in apache.evidence


def test_9_wordpress_detection_from_html_markers():
    """Test 9: WordPress detection from meta generator and wp-content paths."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="https://example.com",
        port=443,
        protocol="tcp",
        service_name="https",
        is_reachable=True,
        headers={"content-type": "text/html"},
        body_snippet=(
            '<html><head>'
            '<meta name="generator" content="WordPress 6.4.3" />'
            '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />'
            '</head><body>Content</body></html>'
        ),
    )

    detected = tech_service.fingerprint_http_observation(obs)

    wp = next((t for t in detected if t.name == "WordPress"), None)
    assert wp is not None
    assert wp.category == "cms"
    assert wp.version == "6.4.3"
    assert wp.cpe == "cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*"
    assert "meta_generator" in wp.evidence_source or "WordPress" in wp.evidence


def test_10_js_framework_detection():
    """Test 10: JavaScript framework detection for React, Vue.js, and Angular."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="https://example.com",
        port=443,
        protocol="tcp",
        service_name="https",
        is_reachable=True,
        headers={"content-type": "text/html"},
        body_snippet=(
            '<html><head><script src="/js/react.production.min.js"></script></head>'
            '<body>'
            '<div id="root" data-reactroot="">'
            '<div data-v-4f8a9b2c class="vue-card">'
            '<div ng-version="17.1.0">Angular App</div>'
            '</div>'
            '</div>'
            '</body></html>'
        ),
    )

    detected = tech_service.fingerprint_http_observation(obs)
    names = {t.name for t in detected}

    assert "React" in names
    assert "Vue.js" in names
    assert "Angular" in names

    angular = next(t for t in detected if t.name == "Angular")
    assert angular.version == "17.1.0"


def test_11_technology_version_extraction_no_guessing():
    """Test 11: Version is None when not observable (no guessing)."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "nginx"},  # No version token
    )

    detected = tech_service.fingerprint_http_observation(obs)

    nginx = next((t for t in detected if t.name == "nginx"), None)
    assert nginx is not None
    assert nginx.version is None
    assert nginx.cpe is None


def test_12_unknown_technology_does_not_produce_false_detection():
    """Test 12: Generic non-matching response produces no false detections."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "ProprietaryServer/9.0", "content-type": "text/plain"},
        body_snippet="OK",
    )

    detected = tech_service.fingerprint_http_observation(obs)
    assert len(detected) == 0


def test_13_duplicate_technology_detection_deduplication():
    """Test 13: Multiple matching rules for the same technology are deduplicated."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "Apache/2.4.50", "x-powered-by": "PHP/8.1.5"},
        cookies={"PHPSESSID": "sess12345"},
    )

    detected = tech_service.fingerprint_http_observation(obs)
    php_detections = [t for t in detected if t.name == "PHP"]

    assert len(php_detections) == 1
    assert php_detections[0].version == "8.1.5"


def test_14_evidence_reason_is_retained():
    """Test 14: Evidence and source description are retained on every detected technology."""
    tech_service = TechnologyService()
    obs = HTTPProbeObservation(
        url="http://example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        headers={"server": "Caddy/v2.7.5"},
    )

    detected = tech_service.fingerprint_http_observation(obs)
    caddy = next((t for t in detected if t.name == "Caddy"), None)

    assert caddy is not None
    assert caddy.version == "2.7.5"
    assert len(caddy.evidence) > 0
    assert len(caddy.evidence_source) > 0


# ==========================================
# 15-23. HTTP SECURITY HEADERS TESTS
# ==========================================

def test_15_security_header_hsts_present():
    """Test 15: HSTS present and configured."""
    headers = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers, is_https=True)

    hsts = analysis["strict_transport_security"]
    assert hsts.present is True
    assert hsts.status == "configured"
    assert "max-age=31536000" in hsts.interpretation
    assert "includeSubDomains" in hsts.interpretation


def test_16_security_header_hsts_absent_on_https():
    """Test 16: HSTS absent on HTTPS is marked missing."""
    headers = {}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers, is_https=True)

    hsts = analysis["strict_transport_security"]
    assert hsts.present is False
    assert hsts.status == "missing"
    assert "not observed" in hsts.interpretation


def test_17_security_header_csp_present():
    """Test 17: Content-Security-Policy present."""
    headers = {"content-security-policy": "default-src 'self'; script-src 'self' https://trusted.cdn"}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers, is_https=True)

    csp = analysis["content_security_policy"]
    assert csp.present is True
    assert csp.status == "configured"
    assert csp.value == "default-src 'self'; script-src 'self' https://trusted.cdn"


def test_18_security_header_csp_absent():
    """Test 18: Content-Security-Policy absent."""
    headers = {}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers, is_https=True)

    csp = analysis["content_security_policy"]
    assert csp.present is False
    assert csp.status == "missing"
    assert "not observed" in csp.interpretation


def test_19_security_header_x_frame_options():
    """Test 19: X-Frame-Options DENY / SAMEORIGIN."""
    headers1 = {"x-frame-options": "DENY"}
    analysis1 = HTTPIntelligenceService.analyze_security_headers(headers1)
    assert analysis1["x_frame_options"].present is True
    assert analysis1["x_frame_options"].status == "configured"
    assert "Clickjacking" in analysis1["x_frame_options"].interpretation

    headers2 = {"x-frame-options": "SAMEORIGIN"}
    analysis2 = HTTPIntelligenceService.analyze_security_headers(headers2)
    assert analysis2["x_frame_options"].present is True
    assert analysis2["x_frame_options"].status == "configured"


def test_20_security_header_x_content_type_options():
    """Test 20: X-Content-Type-Options nosniff."""
    headers = {"x-content-type-options": "nosniff"}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers)

    xcto = analysis["x_content_type_options"]
    assert xcto.present is True
    assert xcto.status == "configured"
    assert "MIME-sniffing" in xcto.interpretation


def test_21_security_header_referrer_policy():
    """Test 21: Referrer-Policy."""
    headers = {"referrer-policy": "strict-origin-when-cross-origin"}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers)

    ref = analysis["referrer_policy"]
    assert ref.present is True
    assert ref.status == "configured"
    assert "strict-origin-when-cross-origin" in ref.interpretation


def test_22_security_header_permissions_policy():
    """Test 22: Permissions-Policy."""
    headers = {"permissions-policy": "geolocation=(), microphone=()"}
    analysis = HTTPIntelligenceService.analyze_security_headers(headers)

    perm = analysis["permissions_policy"]
    assert perm.present is True
    assert perm.status == "configured"


def test_23_security_headers_malformed_values():
    """Test 23: Malformed / unusual header values handled safely without exceptions."""
    headers = {
        "strict-transport-security": "invalid; corrupted;;;",
        "x-frame-options": "ALLOW-FROM https://unsupported.com",
        "x-content-type-options": "random-garbage",
    }
    analysis = HTTPIntelligenceService.analyze_security_headers(headers)

    assert analysis["strict_transport_security"].present is True
    assert analysis["x_frame_options"].present is True
    assert analysis["x_frame_options"].status == "custom"
    assert analysis["x_content_type_options"].present is True
    assert analysis["x_content_type_options"].status == "custom"


# ==========================================
# 24-26. TLS METADATA TESTS
# ==========================================

def test_24_tls_metadata_extraction_mocked():
    """Test 24: Mocked socket TLS metadata extraction with IP pinning and SNI preservation."""
    mock_resolver = make_mock_resolver({"api.example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.3"
    mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_sslsock.getpeercert.return_value = {
        "subject": ((("commonName", "api.example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "subjectAltName": (("DNS", "api.example.com"), ("DNS", "example.com")),
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Jan  1 00:00:00 2025 GMT",
    }

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("socket.create_connection", return_value=mock_sock) as mock_create_conn:
        with patch("ssl.create_default_context", return_value=mock_context):
            tls_info = service._inspect_tls("api.example.com", 443)

            # Verify socket connects directly to validated IP (IP pinning), NOT raw hostname
            mock_create_conn.assert_called_once_with(("93.184.216.34", 443), timeout=service._timeout)
            # Verify SNI is preserved with original hostname
            mock_context.wrap_socket.assert_called_once_with(mock_sock, server_hostname="api.example.com")

    assert tls_info is not None
    assert tls_info.tls_version == "TLSv1.3"
    assert tls_info.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert tls_info.cert_subject == "api.example.com"
    assert tls_info.cert_issuer == "DigiCert Inc"
    assert "api.example.com" in tls_info.cert_san_list


def test_24b_tls_host_resolving_to_private_ip_blocked():
    """Test 24B: Hostname resolving to private/loopback IP is blocked before socket connection."""
    mock_resolver = make_mock_resolver({"private-tls.local": {"A": ["10.0.0.1"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver)

    with patch("socket.create_connection") as mock_create_conn:
        tls_info = service._inspect_tls("private-tls.local", 443)
        mock_create_conn.assert_not_called()

    assert tls_info is None


def test_24c_tls_multiple_addresses_selects_validated_public():
    """Test 24C: Multiple public addresses connect to validated IP; mixed private address rejects."""
    # 1. Pure public multiple IPs
    mock_resolver_pub = make_mock_resolver({
        "multi.example.com": {"A": ["93.184.216.34", "93.184.216.35"]},
    })
    service_pub = HTTPIntelligenceService(resolver=mock_resolver_pub)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.3"
    mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_sslsock.getpeercert.return_value = {}
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("socket.create_connection", return_value=mock_sock) as mock_conn:
        with patch("ssl.create_default_context", return_value=mock_context):
            tls_info = service_pub._inspect_tls("multi.example.com", 443)
            assert mock_conn.call_args[0][0][0] in ("93.184.216.34", "93.184.216.35")
            assert tls_info is not None

    # 2. Mixed public + private address rejects entire host
    mock_resolver_mixed = make_mock_resolver({
        "mixed.example.com": {"A": ["93.184.216.34", "192.168.1.1"]},
    })
    service_mixed = HTTPIntelligenceService(resolver=mock_resolver_mixed)
    with patch("socket.create_connection") as mock_conn:
        tls_info_mixed = service_mixed._inspect_tls("mixed.example.com", 443)
        mock_conn.assert_not_called()
        assert tls_info_mixed is None


def test_24d_tls_dns_rebinding_simulation_uses_pinned_ip():
    """Test 24D: DNS rebinding simulation verifies TLS connection stays pinned to pre-validated IP."""
    mock_resolver = make_mock_resolver({"rebind.example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver)

    # Pre-flight validated IP obtained from probe_service
    validated_ips = service._get_validated_public_ips("rebind.example.com")
    assert validated_ips == ["93.184.216.34"]

    # Simulate attacker flipping DNS resolver to loopback after pre-flight
    mock_resolver_rebound = make_mock_resolver({"rebind.example.com": {"A": ["127.0.0.1"]}})
    service._resolver = mock_resolver_rebound

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.3"
    mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_sslsock.getpeercert.return_value = {}
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("socket.create_connection", return_value=mock_sock) as mock_conn:
        with patch("ssl.create_default_context", return_value=mock_context):
            tls_info = service._inspect_tls("rebind.example.com", 443, validated_ips=validated_ips)

            # Assert socket connected to the pinned IP 93.184.216.34, NEVER 127.0.0.1 or rebind.example.com
            mock_conn.assert_called_once_with(("93.184.216.34", 443), timeout=service._timeout)
            mock_context.wrap_socket.assert_called_once_with(mock_sock, server_hostname="rebind.example.com")
            assert tls_info is not None


def test_24e_tls_ipv6_public_address_supported():
    """Test 24E: Public IPv6 address is pinned and connected properly."""
    mock_resolver = make_mock_resolver({
        "ipv6-sec.example.com": {"AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]},
    })
    service = HTTPIntelligenceService(resolver=mock_resolver)

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.3"
    mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_sslsock.getpeercert.return_value = {}
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("socket.create_connection", return_value=mock_sock) as mock_conn:
        with patch("ssl.create_default_context", return_value=mock_context):
            tls_info = service._inspect_tls("ipv6-sec.example.com", 443)
            mock_conn.assert_called_once_with(
                ("2606:2800:220:1:248:1893:25c8:1946", 443), timeout=service._timeout
            )
            mock_context.wrap_socket.assert_called_once_with(
                mock_sock, server_hostname="ipv6-sec.example.com"
            )
            assert tls_info is not None


def test_25_tls_failure_handled_gracefully():
    """Test 25: TLS handshake or connection failure returns None without raising."""
    mock_resolver = make_mock_resolver({"broken-tls.example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver)

    with patch("socket.create_connection", side_effect=ssl.SSLError("Handshake failed")):
        tls_info = service._inspect_tls("broken-tls.example.com", 443)

    assert tls_info is None


def test_26_http_service_does_not_produce_tls_observations():
    """Test 26: Port 80 HTTP probe does not invoke TLS inspection."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL("http://example.com")
    mock_resp.headers = httpx.Headers({"server": "nginx"})
    mock_resp.cookies = {}
    mock_resp.text = "Hello"
    mock_client.get.return_value = mock_resp

    mock_resolver = make_mock_resolver({"example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    with patch.object(service, "_inspect_tls") as mock_inspect:
        obs = service.probe_service("example.com", 80, protocol="tcp", service_name="http")
        mock_inspect.assert_not_called()

    assert obs.tls_metadata is None


# ==========================================
# 27-29. HISTORICAL SCANRUN ISOLATION TESTS
# ==========================================

def test_27_scan_a_and_scan_b_technology_history():
    """Test 27: Scan A and Scan B technology observations remain isolated."""
    with TestingSessionLocal() as db:
        # Create Target & Investigation
        target = Target(primary_domain="history-tech.example.com", name="History Tech")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code="INV-HIST-TECH-01",
            target_id=target.id,
            title="Tech History Test",
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        )
        db.add(inv)
        db.flush()

        asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="history-tech.example.com",
            is_active=True,
            source="target_scope",
        )
        db.add(asset)
        db.flush()

        # Scan Run A: nginx 1.20
        scan_a = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
        db.add(scan_a)
        db.flush()

        tech_a = Technology(
            asset_id=asset.id,
            scan_run_id=scan_a.id,
            name="nginx",
            version="1.20.0",
            category="web_server",
            confidence=1.0,
            evidence_source="headers",
        )
        db.add(tech_a)

        # Scan Run B: Apache 2.4.52
        scan_b = ScanRun(investigation_id=inv.id, run_number=2, status="completed")
        db.add(scan_b)
        db.flush()

        tech_b = Technology(
            asset_id=asset.id,
            scan_run_id=scan_b.id,
            name="Apache",
            version="2.4.52",
            category="web_server",
            confidence=1.0,
            evidence_source="headers",
        )
        db.add(tech_b)
        db.commit()

        # Query Scan A techs
        scan_a_techs = db.execute(
            select(Technology).where(Technology.scan_run_id == scan_a.id)
        ).scalars().all()
        assert len(scan_a_techs) == 1
        assert scan_a_techs[0].name == "nginx"
        assert scan_a_techs[0].version == "1.20.0"

        # Query Scan B techs
        scan_b_techs = db.execute(
            select(Technology).where(Technology.scan_run_id == scan_b.id)
        ).scalars().all()
        assert len(scan_b_techs) == 1
        assert scan_b_techs[0].name == "Apache"
        assert scan_b_techs[0].version == "2.4.52"


def test_28_scan_a_and_scan_b_security_header_history():
    """Test 28: Scan A and Scan B security header observations remain isolated."""
    with TestingSessionLocal() as db:
        target = Target(primary_domain="history-headers.example.com", name="History Headers")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code="INV-HIST-HDRS-01",
            target_id=target.id,
            title="Headers History Test",
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        )
        db.add(inv)
        db.flush()

        asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="history-headers.example.com",
            is_active=True,
            source="target_scope",
        )
        db.add(asset)
        db.flush()

        # Scan A: Missing HSTS
        scan_a = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
        db.add(scan_a)
        db.flush()

        svc_a = ServiceExposure(
            asset_id=asset.id,
            scan_run_id=scan_a.id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=200,
            security_headers={"strict_transport_security": {"present": False, "status": "missing"}},
        )
        db.add(svc_a)

        # Scan B: Configured HSTS
        scan_b = ScanRun(investigation_id=inv.id, run_number=2, status="completed")
        db.add(scan_b)
        db.flush()

        svc_b = ServiceExposure(
            asset_id=asset.id,
            scan_run_id=scan_b.id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=200,
            security_headers={"strict_transport_security": {"present": True, "status": "configured"}},
        )
        db.add(svc_b)
        db.commit()

        # Verify Scan A
        res_a = db.execute(
            select(ServiceExposure).where(ServiceExposure.scan_run_id == scan_a.id)
        ).scalar_one()
        assert res_a.security_headers["strict_transport_security"]["present"] is False

        # Verify Scan B
        res_b = db.execute(
            select(ServiceExposure).where(ServiceExposure.scan_run_id == scan_b.id)
        ).scalar_one()
        assert res_b.security_headers["strict_transport_security"]["present"] is True


def test_29_repeated_fingerprinting_does_not_duplicate_within_single_scan():
    """Test 29: Single scan run records one technology per unique detection on the service."""
    with TestingSessionLocal() as db:
        target = Target(primary_domain="dedup-scan.example.com", name="Dedup Scan")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code="INV-DEDUP-01",
            target_id=target.id,
            title="Dedup Scan Test",
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        )
        db.add(inv)
        db.flush()

        asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="dedup-scan.example.com",
            is_active=True,
            source="target_scope",
        )
        db.add(asset)
        db.flush()

        scan = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
        db.add(scan)
        db.flush()

        svc = ServiceExposure(
            asset_id=asset.id,
            scan_run_id=scan.id,
            port=80,
            protocol="tcp",
            service_name="http",
            http_status=200,
        )
        db.add(svc)
        db.flush()

        t1 = Technology(asset_id=asset.id, service_id=svc.id, scan_run_id=scan.id, name="nginx", category="web_server", evidence_source="headers")
        db.add(t1)
        db.commit()

        techs = db.execute(
            select(Technology).where(Technology.scan_run_id == scan.id)
        ).scalars().all()
        assert len(techs) == 1


# ==========================================
# 30-34. SSRF & SECURITY CONTROLS TESTS
# ==========================================

def test_30_ssrf_private_ip_blocked():
    """Test 30: Hostnames resolving to private IPs are blocked."""
    mock_resolver = make_mock_resolver({
        "internal.example.local": {"A": ["10.0.0.5"]},
        "corp.example.local": {"A": ["192.168.1.50"]},
    })
    service = HTTPIntelligenceService(resolver=mock_resolver)

    obs1 = service.probe_service("internal.example.local", 80)
    assert obs1.is_reachable is False
    assert "SSRF Blocked" in (obs1.error or "")

    obs2 = service.probe_service("corp.example.local", 80)
    assert obs2.is_reachable is False
    assert "SSRF Blocked" in (obs2.error or "")


def test_31_ssrf_loopback_blocked():
    """Test 31: Hostnames resolving to loopback addresses are blocked."""
    mock_resolver = make_mock_resolver({
        "localhost.test": {"A": ["127.0.0.1"]},
        "ipv6-loop.test": {"AAAA": ["::1"]},
    })
    service = HTTPIntelligenceService(resolver=mock_resolver)

    obs1 = service.probe_service("localhost.test", 80)
    assert obs1.is_reachable is False
    assert "SSRF Blocked" in (obs1.error or "")

    obs2 = service.probe_service("ipv6-loop.test", 80)
    assert obs2.is_reachable is False
    assert "SSRF Blocked" in (obs2.error or "")


def test_32_ssrf_redirect_to_private_destination_blocked():
    """Test 32: HTTP redirect to a private IP is intercepted and blocked."""
    mock_client = MagicMock(spec=httpx.Client)

    # 1st request: 302 to http://192.168.1.1/admin
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 302
    mock_resp1.url = httpx.URL("http://public.example.com")
    mock_resp1.headers = httpx.Headers({"Location": "http://192.168.1.1/admin"})
    mock_resp1.cookies = {}
    mock_resp1.text = ""

    mock_client.get.return_value = mock_resp1

    mock_resolver = make_mock_resolver({
        "public.example.com": {"A": ["93.184.216.34"]},
    })
    service = HTTPIntelligenceService(client=mock_client, resolver=mock_resolver)

    obs = service.probe_service("public.example.com", 80)

    assert obs.is_reachable is False
    assert "SSRF Redirect Blocked" in (obs.error or "")


def test_33_arbitrary_frontend_url_cannot_be_supplied():
    """Test 33: Confirm no arbitrary URL fetch endpoint exists."""
    headers = get_auth_headers("analyst_one")
    resp = client.post("/api/fetch-url", json={"url": "http://169.254.169.254"}, headers=headers)
    assert resp.status_code == 404


def test_34_existing_stage_3b_ssrf_protections_intact():
    """Test 34: Pre-flight resolved IPs with non-public addresses are blocked upfront."""
    service = HTTPIntelligenceService()

    obs = service.probe_service(
        hostname="cloud-internal.test",
        port=80,
        resolved_ips=["169.254.169.254", "10.200.0.1"],
    )

    assert obs.is_reachable is False
    assert "SSRF Pre-flight" in (obs.error or "") or "SSRF Blocked" in (obs.error or "")


# ==========================================
# 35-38. API & RBAC ENDPOINT TESTS
# ==========================================

def test_35_fingerprint_unauthenticated_request_rejected():
    """Test 35: Unauthenticated request to fingerprint endpoint returns 401."""
    fake_id = uuid.uuid4()
    resp = client.post(f"/api/investigations/{fake_id}/fingerprint")
    assert resp.status_code == 401


def test_36_fingerprint_unauthorized_investigation_access_rejected():
    """Test 36: Analyst B cannot trigger fingerprinting on Analyst A's investigation (403)."""
    with TestingSessionLocal() as db:
        target = Target(primary_domain="auth-iso.example.com", name="Auth Iso")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code="INV-AUTH-ISO-01",
            target_id=target.id,
            title="Analyst A Investigation",
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),  # Analyst 1
        )
        db.add(inv)
        db.commit()
        inv_id = inv.id

    # Analyst 2 attempts access
    headers_analyst2 = get_auth_headers("analyst_two")
    resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers_analyst2)
    assert resp.status_code == 403


def test_37_fingerprint_authorized_analyst_and_admin_success():
    """Test 37: Authorized owner can run fingerprinting and query results."""
    with TestingSessionLocal() as db:
        target = Target(primary_domain="e2e-fingerprint.example.com", name="E2E Target")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code="INV-E2E-FP-01",
            target_id=target.id,
            title="E2E FP Test",
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),  # Analyst 1
        )
        db.add(inv)
        db.flush()

        asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="e2e-fingerprint.example.com",
            is_active=True,
            source="target_scope",
        )
        db.add(asset)
        db.flush()

        domain_rec = Domain(asset_id=asset.id, domain_name="e2e-fingerprint.example.com")
        db.add(domain_rec)
        db.flush()

        sub = Subdomain(
            asset_id=asset.id,
            domain_id=domain_rec.id,
            subdomain_name="e2e-fingerprint.example.com",
            is_resolving=True,
        )
        db.add(sub)
        db.flush()

        dns_rec = DNSRecord(
            subdomain_id=sub.id,
            record_type="A",
            value="93.184.216.34",
            resolver="test_resolver",
        )
        db.add(dns_rec)
        db.commit()
        inv_id = inv.id

    # Mock HTTP probe
    mock_obs_http = HTTPProbeObservation(
        url="http://e2e-fingerprint.example.com",
        port=80,
        protocol="tcp",
        service_name="http",
        is_reachable=True,
        status_code=200,
        page_title="E2E Portal",
        server_header="nginx/1.22.0",
        headers={"server": "nginx/1.22.0", "content-type": "text/html"},
        body_snippet="<html><title>E2E Portal</title><body>Welcome</body></html>",
        security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "nginx/1.22.0"}, is_https=False),
    )

    mock_obs_https = HTTPProbeObservation(
        url="https://e2e-fingerprint.example.com",
        port=443,
        protocol="tcp",
        service_name="https",
        is_reachable=True,
        status_code=200,
        page_title="E2E Portal Secure",
        server_header="nginx/1.22.0",
        headers={"server": "nginx/1.22.0", "strict-transport-security": "max-age=31536000"},
        body_snippet="<html><title>E2E Portal Secure</title></html>",
        security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "nginx/1.22.0", "strict-transport-security": "max-age=31536000"}, is_https=True),
        tls_metadata=TLSMetadata(tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384"),
    )

    mock_http_svc = MagicMock()
    mock_http_svc.probe_service.side_effect = [mock_obs_http, mock_obs_https]

    app.dependency_overrides[get_http_intelligence_service] = lambda: mock_http_svc

    try:
        headers_analyst1 = get_auth_headers("analyst_one")
        resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers_analyst1)
        assert resp.status_code == 200

        data = resp.json()
        assert data["services_processed"] == 2
        assert data["reachable"] == 2
        assert data["technologies_detected"] >= 2
        assert len(data["results"]) == 2

        # Test query endpoints
        tech_resp = client.get(f"/api/investigations/{inv_id}/technologies", headers=headers_analyst1)
        assert tech_resp.status_code == 200
        techs = tech_resp.json()
        assert len(techs) >= 2
        assert any(t["name"] == "nginx" for t in techs)

        sec_resp = client.get(f"/api/investigations/{inv_id}/security-headers", headers=headers_analyst1)
        assert sec_resp.status_code == 200
        assert len(sec_resp.json()) == 2

        tls_resp = client.get(f"/api/investigations/{inv_id}/tls-metadata", headers=headers_analyst1)
        assert tls_resp.status_code == 200
        assert len(tls_resp.json()) == 1

    finally:
        app.dependency_overrides.pop(get_http_intelligence_service, None)


def test_38_fingerprint_invalid_investigation_id():
    """Test 38: Non-existent investigation ID returns 404."""
    headers = get_auth_headers("analyst_one")
    fake_id = uuid.uuid4()
    resp = client.post(f"/api/investigations/{fake_id}/fingerprint", headers=headers)
    assert resp.status_code == 404


def test_39_bounded_concurrent_fingerprinting_multiple_hosts():
    """Test 39: Bounded concurrent fingerprinting across multiple distinct subdomains."""
    with TestingSessionLocal() as db:
        target = Target(name="Concurrent Test Target", primary_domain="concurrent-test.com")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-CONC-{uuid.uuid4().hex[:6]}",
            title="Concurrent Fingerprint Inv",
            target_id=target.id,
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            status="active",
        )
        db.add(inv)
        db.flush()

        domain_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="concurrent-test.com",
            is_active=True,
            source="target_scope",
        )
        db.add(domain_asset)
        db.flush()

        domain_rec = Domain(asset_id=domain_asset.id, domain_name="concurrent-test.com")
        db.add(domain_rec)
        db.flush()

        # Create 5 subdomains
        hostnames = [f"node{i}.concurrent-test.com" for i in range(1, 6)]
        for h in hostnames:
            asset = Asset(
                target_id=target.id,
                investigation_id=inv.id,
                asset_type="subdomain",
                value=h,
                is_active=True,
                source="test",
            )
            db.add(asset)
            db.flush()
            sub = Subdomain(
                asset_id=asset.id,
                domain_id=domain_rec.id,
                subdomain_name=h,
                is_resolving=True,
            )
            db.add(sub)
            db.flush()
            dns_rec = DNSRecord(
                subdomain_id=sub.id,
                record_type="A",
                value="93.184.216.34",
                resolver="test_resolver",
            )
            db.add(dns_rec)
        db.commit()
        inv_id = inv.id

    def mock_probe(hostname, port, protocol, service_name, resolved_ips=None):
        return HTTPProbeObservation(
            url=f"{service_name}://{hostname}:{port}",
            port=port,
            protocol=protocol,
            service_name=service_name,
            is_reachable=True,
            status_code=200,
            page_title=f"Title for {hostname}",
            server_header="Apache/2.4.52 (Ubuntu)",
            headers={"server": "Apache/2.4.52 (Ubuntu)"},
            body_snippet=f"<html><title>Title for {hostname}</title></html>",
            security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "Apache/2.4.52"}, is_https=(service_name == "https")),
            tls_metadata=TLSMetadata(tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384") if service_name == "https" else None,
        )

    mock_http_svc = MagicMock()
    mock_http_svc.probe_service.side_effect = mock_probe

    app.dependency_overrides[get_http_intelligence_service] = lambda: mock_http_svc

    try:
        headers = get_auth_headers("analyst_one")
        resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["services_processed"] == 12  # 1 domain + 5 subdomains = 6 hosts * 2 ports = 12
        assert data["reachable"] == 12
        assert data["technologies_detected"] >= 12
        assert data["tls_observations"] == 6
        assert data["timeouts_count"] == 0
        assert data["ssrf_skips_count"] == 0
        assert data["warnings_count"] == 0
        assert len(data["results"]) == 12
    finally:
        app.dependency_overrides.pop(get_http_intelligence_service, None)


def test_40_http_and_tls_timeout_resilience_and_scanrun_warning_semantics():
    """Test 40: Unresponsive hosts timing out in HTTP/TLS result in completed_with_warnings without failing stage."""
    with TestingSessionLocal() as db:
        target = Target(name="Timeout Test Target", primary_domain="timeout-test.com")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-TO-{uuid.uuid4().hex[:6]}",
            title="Timeout Inv",
            target_id=target.id,
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            status="active",
        )
        db.add(inv)
        db.flush()

        domain_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="timeout-test.com",
            is_active=True,
            source="target_scope",
        )
        db.add(domain_asset)
        db.flush()

        domain_rec = Domain(asset_id=domain_asset.id, domain_name="timeout-test.com")
        db.add(domain_rec)
        db.flush()

        # 1 responsive host, 1 timeout host
        for h in ["good.timeout-test.com", "dead.timeout-test.com"]:
            asset = Asset(
                target_id=target.id,
                investigation_id=inv.id,
                asset_type="subdomain",
                value=h,
                is_active=True,
                source="test",
            )
            db.add(asset)
            db.flush()
            sub = Subdomain(
                asset_id=asset.id,
                domain_id=domain_rec.id,
                subdomain_name=h,
                is_resolving=True,
            )
            db.add(sub)
            db.flush()
            dns_rec = DNSRecord(
                subdomain_id=sub.id,
                record_type="A",
                value="93.184.216.34",
                resolver="test_resolver",
            )
            db.add(dns_rec)
        db.commit()
        inv_id = inv.id

    def mock_probe(hostname, port, protocol, service_name, resolved_ips=None):
        if "dead" in hostname:
            return HTTPProbeObservation(
                url=f"{service_name}://{hostname}:{port}",
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=False,
                error="Connection timed out after 2.0s",
            )
        return HTTPProbeObservation(
            url=f"{service_name}://{hostname}:{port}",
            port=port,
            protocol=protocol,
            service_name=service_name,
            is_reachable=True,
            status_code=200,
            page_title="Good Host",
            server_header="nginx/1.22",
            headers={"server": "nginx/1.22"},
            security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "nginx/1.22"}, is_https=(service_name == "https")),
            tls_metadata=TLSMetadata(tls_version="TLSv1.3") if service_name == "https" else None,
        )

    mock_http_svc = MagicMock()
    mock_http_svc.probe_service.side_effect = mock_probe

    app.dependency_overrides[get_http_intelligence_service] = lambda: mock_http_svc

    try:
        headers = get_auth_headers("analyst_one")
        resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed_with_warnings"
        # 3 hosts (domain + 2 subdomains) * 2 ports = 6 services processed
        assert data["services_processed"] == 6
        assert data["reachable"] == 4  # domain (2) + good (2)
        assert data["timeouts_count"] == 2  # dead (2)
        assert data["warnings_count"] == 2
        assert len(data["results"]) == 4  # Only reachable services persisted
    finally:
        app.dependency_overrides.pop(get_http_intelligence_service, None)


def test_41_duplicate_host_deduplication_within_scanrun():
    """Test 41: Duplicate assets with same hostname only trigger one probe execution per port."""
    with TestingSessionLocal() as db:
        target = Target(name="Dedup Target", primary_domain="dedup-test.com")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-DEDUP-{uuid.uuid4().hex[:6]}",
            title="Dedup Inv",
            target_id=target.id,
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            status="active",
        )
        db.add(inv)
        db.flush()

        domain_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="dedup-test.com",
            is_active=True,
            source="target_scope",
        )
        db.add(domain_asset)
        db.flush()

        domain_rec = Domain(asset_id=domain_asset.id, domain_name="dedup-test.com")
        db.add(domain_rec)
        db.flush()

        # Two assets pointing to the same hostname 'shared.dedup-test.com'
        for _ in range(2):
            asset = Asset(
                target_id=target.id,
                investigation_id=inv.id,
                asset_type="subdomain",
                value="shared.dedup-test.com",
                is_active=True,
                source="test",
            )
            db.add(asset)
            db.flush()
            sub = Subdomain(
                asset_id=asset.id,
                domain_id=domain_rec.id,
                subdomain_name="shared.dedup-test.com",
                is_resolving=True,
            )
            db.add(sub)
            db.flush()
            dns_rec = DNSRecord(
                subdomain_id=sub.id,
                record_type="A",
                value="93.184.216.34",
                resolver="test_resolver",
            )
            db.add(dns_rec)
        db.commit()
        inv_id = inv.id

    probe_calls = []

    def mock_probe(hostname, port, protocol, service_name, resolved_ips=None):
        probe_calls.append((hostname, port))
        return HTTPProbeObservation(
            url=f"{service_name}://{hostname}:{port}",
            port=port,
            protocol=protocol,
            service_name=service_name,
            is_reachable=True,
            status_code=200,
            page_title="Dedup Host",
            server_header="cloudflare",
            headers={"server": "cloudflare"},
            security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "cloudflare"}, is_https=(service_name == "https")),
            tls_metadata=TLSMetadata(tls_version="TLSv1.3") if service_name == "https" else None,
        )

    mock_http_svc = MagicMock()
    mock_http_svc.probe_service.side_effect = mock_probe

    app.dependency_overrides[get_http_intelligence_service] = lambda: mock_http_svc

    try:
        headers = get_auth_headers("analyst_one")
        resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        # Unique hosts: dedup-test.com (2 ports) and shared.dedup-test.com (2 ports) = 4 probes total
        # The duplicate shared.dedup-test.com asset was not probed a second time
        assert len(probe_calls) == 4
        assert sorted(probe_calls) == [
            ("dedup-test.com", 80),
            ("dedup-test.com", 443),
            ("shared.dedup-test.com", 80),
            ("shared.dedup-test.com", 443),
        ]
        # Results detail map to all 3 assets (6 service exposures)
        assert data["services_processed"] == 6
        assert data["reachable"] == 6
    finally:
        app.dependency_overrides.pop(get_http_intelligence_service, None)


def test_42_ssrf_private_ip_skips_not_treated_as_failures():
    """Test 42: SSRF skips on private/reserved IPs increment ssrf_skips_count without causing completed_with_warnings status."""
    with TestingSessionLocal() as db:
        target = Target(name="SSRF Skip Target", primary_domain="ssrf-skip-test.com")
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-SSRF-{uuid.uuid4().hex[:6]}",
            title="SSRF Skip Inv",
            target_id=target.id,
            created_by_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            status="active",
        )
        db.add(inv)
        db.flush()

        domain_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value="ssrf-skip-test.com",
            is_active=True,
            source="target_scope",
        )
        db.add(domain_asset)
        db.flush()

        domain_rec = Domain(asset_id=domain_asset.id, domain_name="ssrf-skip-test.com")
        db.add(domain_rec)
        db.flush()

        # 1 public host, 1 internal host resolving to private IP
        for h, ip in [("pub.ssrf-skip-test.com", "93.184.216.34"), ("internal.ssrf-skip-test.com", "10.0.0.1")]:
            asset = Asset(
                target_id=target.id,
                investigation_id=inv.id,
                asset_type="subdomain",
                value=h,
                is_active=True,
                source="test",
            )
            db.add(asset)
            db.flush()
            sub = Subdomain(
                asset_id=asset.id,
                domain_id=domain_rec.id,
                subdomain_name=h,
                is_resolving=True,
            )
            db.add(sub)
            db.flush()
            dns_rec = DNSRecord(
                subdomain_id=sub.id,
                record_type="A",
                value=ip,
                resolver="test_resolver",
            )
            db.add(dns_rec)
        db.commit()
        inv_id = inv.id

    def mock_probe(hostname, port, protocol, service_name, resolved_ips=None):
        if "internal" in hostname:
            return HTTPProbeObservation(
                url=f"{service_name}://{hostname}:{port}",
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=False,
                error="SSRF: Hostname 'internal.ssrf-skip-test.com' resolved only to non-public/reserved IPs: ['10.0.0.1']. Probe aborted.",
            )
        return HTTPProbeObservation(
            url=f"{service_name}://{hostname}:{port}",
            port=port,
            protocol=protocol,
            service_name=service_name,
            is_reachable=True,
            status_code=200,
            page_title="Public Host",
            server_header="nginx",
            headers={"server": "nginx"},
            security_headers=HTTPIntelligenceService.analyze_security_headers({"server": "nginx"}, is_https=(service_name == "https")),
            tls_metadata=TLSMetadata(tls_version="TLSv1.3") if service_name == "https" else None,
        )

    mock_http_svc = MagicMock()
    mock_http_svc.probe_service.side_effect = mock_probe

    app.dependency_overrides[get_http_intelligence_service] = lambda: mock_http_svc

    try:
        headers = get_auth_headers("analyst_one")
        resp = client.post(f"/api/investigations/{inv_id}/fingerprint", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        # SSRF skips are expected security behaviour -> status remains 'completed' and warnings_count is 0
        assert data["status"] == "completed"
        assert data["ssrf_skips_count"] == 2
        assert data["timeouts_count"] == 0
        assert data["warnings_count"] == 0
        assert data["reachable"] == 4  # domain (2) + pub (2)
    finally:
        app.dependency_overrides.pop(get_http_intelligence_service, None)


def test_43_redirect_ssrf_validation_blocks_internal_hop():
    """Test 43: Redirect to internal/private IP during HTTP probe is blocked."""
    mock_resolver = make_mock_resolver({
        "public-hop.com": {"A": ["93.184.216.34"]},
        "private-dest.local": {"A": ["192.168.1.1"]},
    })
    service = HTTPIntelligenceService(resolver=mock_resolver)

    mock_redirect_response = MagicMock()
    mock_redirect_response.status_code = 302
    mock_redirect_response.headers = {"location": "http://private-dest.local/admin"}
    mock_redirect_response.is_redirect = True

    mock_client = MagicMock()
    mock_client.get.return_value = mock_redirect_response
    service._client = mock_client

    obs = service._execute_http_probe(
        target_url="http://public-hop.com",
        hostname="public-hop.com",
        port=80,
        protocol="tcp",
        service_name="http",
        tls_info=None,
    )

    # Initial request worked, but redirect to 192.168.1.1 was blocked
    assert obs.is_reachable is False
    assert "SSRF Redirect Blocked" in (obs.error or "")


def test_44_tls_timeout_socket_error_handling():
    """Test 44: TLS socket connect / handshake timeout returns None cleanly."""
    mock_resolver = make_mock_resolver({"slow-tls.example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver, timeout=1.0)

    with patch("socket.create_connection", side_effect=socket.timeout("Socket connection timed out")):
        tls_info = service._inspect_tls("slow-tls.example.com", 443)
        assert tls_info is None


def test_45_dns_ip_validation_cache_thread_safety():
    """Test 45: HTTPIntelligenceService DNS validation cache caches public IP validations."""
    mock_resolver = make_mock_resolver({"cached.example.com": {"A": ["93.184.216.34"]}})
    service = HTTPIntelligenceService(resolver=mock_resolver)

    ips1 = service._get_validated_public_ips("cached.example.com")
    assert ips1 == ["93.184.216.34"]
    assert mock_resolver.resolve.call_count == 2  # A + AAAA

    # Second call should use memory cache without re-querying DNS resolver
    ips2 = service._get_validated_public_ips("cached.example.com")
    assert ips2 == ["93.184.216.34"]
    assert mock_resolver.resolve.call_count == 2  # Unchanged


