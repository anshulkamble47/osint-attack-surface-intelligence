"""Comprehensive test suite for Stage 3A: Investigation Management and Certificate Transparency Discovery."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database.base import Base
from backend.app.database.connection import get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Subdomain
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.ct_service import CTService, CrtShProvider, CTProviderError
from backend.app.utils.domain import normalize_domain, is_valid_domain, is_subdomain_of
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Helper Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_ct_test_users():
    """Ensure required test users exist in database without wiping other test data."""
    with TestingSessionLocal() as db:
        users_to_seed = [
            (uuid.UUID("11111111-1111-1111-1111-111111111111"), "analyst1@security.local", "analyst_one", "analyst"),
            (uuid.UUID("22222222-2222-2222-2222-222222222222"), "analyst2@security.local", "analyst_two", "analyst"),
            (uuid.UUID("33333333-3333-3333-3333-333333333333"), "admin@security.local", "root_admin", "admin"),
        ]
        for u_id, email, username, role in users_to_seed:
            user = db.get(User, u_id)
            if not user:
                user_by_email = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
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
    """Generate Bearer authorization headers for a test user by querying their DB record."""
    with TestingSessionLocal() as db:
        user = db.execute(select(User).where(User.username == username)).scalar_one()
        token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
        return {"Authorization": f"Bearer {token}"}


# --- 1. Domain Utility Tests ---

def test_domain_normalization_and_boundary_validation():
    """Verify URL stripping, port removal, lowercase conversion, and wildcard handling."""
    assert normalize_domain("https://Example.COM:8080/path?arg=1") == "example.com"
    assert normalize_domain("http://sub.example.com/") == "sub.example.com"
    assert normalize_domain("  EXAMPLE.COM.  ") == "example.com"
    assert normalize_domain("*.api.example.com") == "api.example.com"
    assert normalize_domain("*..example.com") == "example.com"

    # Domain syntax validation
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.domain.example.co.uk") is True
    assert is_valid_domain("not a domain") is False
    assert is_valid_domain("192.168.1.1") is False  # Disallow IP
    assert is_valid_domain("localhost") is False
    assert is_valid_domain("") is False
    assert is_valid_domain("example..com") is False

    # Strict domain boundary validation (prevent substring poisoning)
    assert is_subdomain_of("example.com", "example.com") is True
    assert is_subdomain_of("api.example.com", "example.com") is True
    assert is_subdomain_of("dev.api.example.com", "example.com") is True
    assert is_subdomain_of("notexample.com", "example.com") is False
    assert is_subdomain_of("example.com.attacker.com", "example.com") is False
    assert is_subdomain_of("google.com", "example.com") is False


# --- 2. Investigation Creation & Access Control Tests ---

def test_investigation_creation_requires_authentication():
    """Verify that creating an investigation without token returns 401 Unauthorized."""
    payload = {"name": "Unauthorized Investigation", "target_domain": "example.com"}
    response = client.post("/api/investigations", json=payload)
    assert response.status_code == 401


def test_investigation_creation_valid_domain_normalization():
    """Verify that an authenticated user can create an investigation and domain is normalized."""
    headers = get_auth_headers("analyst_one")
    payload = {
        "name": "Acme Attack Surface Assessment",
        "target_domain": "HTTPS://AcmeCorp.COM:443/audit-scope",
        "organization": "Acme Corporation",
        "description": "Primary OSINT scan scope",
    }
    response = client.post("/api/investigations", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()

    assert data["target_domain"] == "acmecorp.com"
    assert data["title"] == "Acme Attack Surface Assessment"
    assert data["status"] == "pending"
    assert "created_by_id" in data
    assert data["reference_code"].startswith("INV-")

    # Verify Target and root Asset were created in database
    with TestingSessionLocal() as db:
        target = db.execute(select(Target).where(Target.primary_domain == "acmecorp.com")).scalar_one()
        assert target.name == "Acme Corporation"

        asset = db.execute(
            select(Asset).where(Asset.value == "acmecorp.com", Asset.investigation_id == uuid.UUID(data["id"]))
        ).scalar_one()
        assert asset.asset_type == "domain"
        assert asset.is_active is True


def test_investigation_creation_invalid_domain_rejection():
    """Verify invalid domain inputs are rejected with 422 Unprocessable Entity."""
    headers = get_auth_headers("analyst_one")

    # Invalid characters
    res1 = client.post("/api/investigations", json={"name": "Test", "target_domain": "invalid domain with spaces"}, headers=headers)
    assert res1.status_code == 422

    # IP address passed as domain
    res2 = client.post("/api/investigations", json={"name": "Test", "target_domain": "192.168.1.1"}, headers=headers)
    assert res2.status_code == 422


def test_investigation_ownership_and_access_isolation():
    """
    Verify access control:
    - Analyst 1 creates Investigation 1.
    - Analyst 2 cannot view or trigger scans on Investigation 1 (403 Forbidden).
    - Admin CAN view and access Investigation 1.
    """
    headers1 = get_auth_headers("analyst_one")
    headers2 = get_auth_headers("analyst_two")
    admin_headers = get_auth_headers("root_admin")

    # Analyst 1 creates investigation
    create_res = client.post(
        "/api/investigations",
        json={"name": "Alice Private Assessment", "target_domain": "alice-target.com"},
        headers=headers1,
    )
    assert create_res.status_code == 201
    inv_id = create_res.json()["id"]

    # Analyst 1 can view
    assert client.get(f"/api/investigations/{inv_id}", headers=headers1).status_code == 200

    # Analyst 2 is rejected
    res_denied = client.get(f"/api/investigations/{inv_id}", headers=headers2)
    assert res_denied.status_code == 403
    assert "not authorized" in res_denied.json()["detail"].lower()

    # Admin can view
    assert client.get(f"/api/investigations/{inv_id}", headers=admin_headers).status_code == 200


# --- 3. Certificate Transparency Discovery Tests (Mocked Provider) ---

MOCK_CRT_SH_RAW_DATA = [
    {
        "id": 1001,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\n*.api.example.com\nauth.example.com",
        "entry_timestamp": "2025-01-01T00:00:00",
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2025-04-01T00:00:00",
        "serial_number": "00aabbcc112233",
    },
    {
        "id": 1002,
        "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256",
        "common_name": "mail.example.com",
        "name_value": "mail.example.com\nlegacy-vpn.example.com\n*.unrelateddomain.com\nnotexample.com",
        "entry_timestamp": "2024-06-01T00:00:00",
        "not_before": "2024-06-01T00:00:00",
        "not_after": "2025-06-01T00:00:00",
        "serial_number": "00ddeeff445566",
    },
    {
        # Duplicate cert record for deduplication verification
        "id": 1003,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "api.example.com",
        "name_value": "api.example.com",
        "entry_timestamp": "2025-01-01T00:00:00",
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2025-04-01T00:00:00",
        "serial_number": "00aabbcc112233",
    },
]


def test_ct_service_parsing_normalization_and_san_filtering():
    """
    Unit test for CTService:
    - Normalizes wildcard hosts (*.api.example.com -> api.example.com)
    - Deduplicates identical hostnames
    - Excludes unrelated domains (*.unrelateddomain.com, notexample.com)
    - Deduplicates certificates
    """
    mock_provider = MagicMock(spec=CrtShProvider)
    mock_provider.name = "crt.sh"
    mock_provider.fetch_certificates.return_value = MOCK_CRT_SH_RAW_DATA

    ct_service = CTService(provider=mock_provider)
    result = ct_service.discover("example.com")

    assert result.target_domain == "example.com"
    assert result.source == "crt.sh"

    # Verify discovered hostnames
    expected_hostnames = {
        "example.com",
        "api.example.com",
        "auth.example.com",
        "mail.example.com",
        "legacy-vpn.example.com",
    }
    assert set(result.hostnames) == expected_hostnames

    # Ensure out-of-scope hostnames are excluded
    assert "notexample.com" not in result.hostnames
    assert "unrelateddomain.com" not in result.hostnames

    # Verify certificate deduplication (2 unique cert serial numbers/fingerprints)
    assert len(result.certificates) == 2


def test_ct_discovery_endpoint_end_to_end_flow():
    """
    Integration test:
    - Creates investigation
    - Executes POST /api/investigations/{id}/discover/ct with mocked CT provider
    - Verifies response schema
    - Verifies DB entities (ScanRun, Assets, Subdomains, Certificates, subdomain_certificates)
    - Verifies CT candidates are NOT marked active (is_active=False, is_resolving=False)
    """
    headers = get_auth_headers("analyst_one")

    # 1. Create Investigation
    inv_res = client.post(
        "/api/investigations",
        json={"name": "CT Recon Scan", "target_domain": "example.com"},
        headers=headers,
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Run CT Discovery with mocked provider
    with patch("backend.app.api.investigations.CTService") as MockCTServiceClass:
        mock_service_instance = MagicMock()
        mock_provider = MagicMock()
        mock_provider.name = "crt.sh"
        mock_provider.fetch_certificates.return_value = MOCK_CRT_SH_RAW_DATA
        real_service = CTService(provider=mock_provider)

        # Let the mock execute real normalization logic
        mock_service_instance.discover.side_effect = real_service.discover
        MockCTServiceClass.return_value = mock_service_instance

        ct_response = client.post(
            f"/api/investigations/{inv_id}/discover/ct",
            headers=headers,
        )

    assert ct_response.status_code == 200
    data = ct_response.json()

    assert data["investigation_id"] == inv_id
    assert data["target_domain"] == "example.com"
    assert data["hostname_count"] == 5
    assert data["certificate_count"] == 2
    assert "api.example.com" in data["hostnames"]
    assert "legacy-vpn.example.com" in data["hostnames"]
    assert "candidate assets" in data["note"].lower()

    # 3. Verify Database State
    with TestingSessionLocal() as db:
        inv_db = db.get(Investigation, uuid.UUID(inv_id))
        assert inv_db.status == "active"
        assert len(inv_db.scan_runs) == 1
        scan_run = inv_db.scan_runs[0]
        assert scan_run.status == "completed"
        assert scan_run.total_discovered_assets == 5

        # Check Asset records for this investigation
        assets = db.execute(
            select(Asset).where(Asset.investigation_id == uuid.UUID(inv_id))
        ).scalars().all()
        assert len(assets) == 5

        # Subdomains discovered via CT must be candidate-only (is_active=False)
        subdomain_assets = [a for a in assets if a.value != "example.com"]
        for sa in subdomain_assets:
            assert sa.is_active is False
            assert sa.source == "crt.sh"
            assert sa.last_scan_run_id == scan_run.id

        # Check Subdomain entities
        subdomains = db.execute(select(Subdomain)).scalars().all()
        assert len(subdomains) == 4  # 4 subdomains (excluding root domain)
        for s in subdomains:
            assert s.is_resolving is False  # Not active yet until Stage 3B DNS
            assert s.discovery_source == "crt.sh"

        # Check Certificates
        certs = db.execute(select(Certificate)).scalars().all()
        assert len(certs) == 2

        # Check subdomain_certificates association table
        associations = db.execute(select(subdomain_certificates)).all()
        assert len(associations) > 0


def test_ct_discovery_graceful_error_handling_on_provider_failure():
    """Verify that external CT provider timeouts / HTTP 502s return structured 502 errors without crashing."""
    headers = get_auth_headers("analyst_one")

    # Create Investigation
    inv_res = client.post(
        "/api/investigations",
        json={"name": "CT Error Test", "target_domain": "fail-target.com"},
        headers=headers,
    )
    inv_id = inv_res.json()["id"]

    # Mock CT Service failure
    with patch("backend.app.api.investigations.CTService") as MockCTServiceClass:
        mock_instance = MagicMock()
        mock_instance.discover.side_effect = CTProviderError("Connection timeout to crt.sh")
        MockCTServiceClass.return_value = mock_instance

        res = client.post(
            f"/api/investigations/{inv_id}/discover/ct",
            headers=headers,
        )

    assert res.status_code == 502
    assert "Certificate Transparency provider error" in res.json()["detail"]

    # Verify ScanRun recorded failure
    with TestingSessionLocal() as db:
        scan_run = db.execute(
            select(ScanRun).where(ScanRun.investigation_id == uuid.UUID(inv_id))
        ).scalar_one()
        assert scan_run.status == "failed"


def test_list_investigation_assets():
    """Verify GET /api/investigations/{id}/assets lists all discovered assets."""
    headers = get_auth_headers("analyst_one")

    # Create Investigation
    inv_res = client.post(
        "/api/investigations",
        json={"name": "Asset List Test", "target_domain": "assets.test.com"},
        headers=headers,
    )
    inv_id = inv_res.json()["id"]

    # Fetch assets (initially has root domain asset)
    asset_res = client.get(f"/api/investigations/{inv_id}/assets", headers=headers)
    assert asset_res.status_code == 200
    assets = asset_res.json()
    assert len(assets) == 1
    assert assets[0]["value"] == "assets.test.com"
    assert assets[0]["asset_type"] == "domain"


# --- 4. CrtShProvider Resilient Retry & Failure Tests ---

def test_crtsh_provider_retry_on_502_success():
    """Verify CrtShProvider recovers when first attempt returns 502 and second attempt returns 200."""
    mock_client = MagicMock()
    res_502 = MagicMock()
    res_502.status_code = 502
    res_502.headers = {"content-type": "text/html"}
    res_502.text = "<html>502 Bad Gateway</html>"

    res_200 = MagicMock()
    res_200.status_code = 200
    res_200.headers = {"content-type": "application/json"}
    res_200.text = '[{"id": 1, "common_name": "example.com", "name_value": "example.com"}]'
    res_200.json.return_value = [{"id": 1, "common_name": "example.com", "name_value": "example.com"}]

    mock_client.get.side_effect = [res_502, res_200]

    provider = CrtShProvider(client=mock_client, timeout=0.1, max_retries=3)
    certs = provider.fetch_certificates("example.com")

    assert len(certs) == 1
    assert certs[0]["common_name"] == "example.com"
    assert mock_client.get.call_count == 2


def test_crtsh_provider_retry_on_timeout_success():
    """Verify CrtShProvider recovers when first attempt times out and second attempt returns 200."""
    import httpx
    mock_client = MagicMock()

    res_200 = MagicMock()
    res_200.status_code = 200
    res_200.headers = {"content-type": "application/json"}
    res_200.text = '[{"id": 2, "common_name": "test.com", "name_value": "test.com"}]'
    res_200.json.return_value = [{"id": 2, "common_name": "test.com", "name_value": "test.com"}]

    mock_client.get.side_effect = [httpx.TimeoutException("Read timed out"), res_200]

    provider = CrtShProvider(client=mock_client, timeout=0.1, max_retries=3)
    certs = provider.fetch_certificates("test.com")

    assert len(certs) == 1
    assert certs[0]["id"] == 2
    assert mock_client.get.call_count == 2


def test_crtsh_provider_404_returns_empty_list():
    """Verify CrtShProvider returns empty list when crt.sh returns 404 Not Found."""
    mock_client = MagicMock()
    res_404 = MagicMock()
    res_404.status_code = 404
    res_404.headers = {"content-type": "text/html"}
    res_404.text = "Not found"
    mock_client.get.return_value = res_404

    provider = CrtShProvider(client=mock_client, timeout=0.1, max_retries=2)
    certs = provider.fetch_certificates("nonexistent-domain-xyz.com")
    assert certs == []


def test_crtsh_provider_exhausted_retries_raises_ct_provider_error():
    """Verify CrtShProvider raises CTProviderError when all retries and fallback queries fail with 502."""
    mock_client = MagicMock()
    res_502 = MagicMock()
    res_502.status_code = 502
    res_502.headers = {"content-type": "text/html"}
    res_502.text = "<html>502 Bad Gateway</html>"
    mock_client.get.return_value = res_502

    provider = CrtShProvider(client=mock_client, timeout=0.1, max_retries=2)
    with pytest.raises(CTProviderError) as exc_info:
        provider.fetch_certificates("always-failing.com")

    assert "Certificate Transparency provider unavailable (HTTP 502)" in str(exc_info.value)


def test_crtsh_provider_unrecoverable_403_raises_ct_provider_error():
    """Verify CrtShProvider immediately raises CTProviderError on HTTP 403 Forbidden."""
    mock_client = MagicMock()
    res_403 = MagicMock()
    res_403.status_code = 403
    res_403.headers = {"content-type": "text/html"}
    res_403.text = "Forbidden"
    mock_client.get.return_value = res_403

    provider = CrtShProvider(client=mock_client, timeout=0.1, max_retries=2)
    with pytest.raises(CTProviderError) as exc_info:
        provider.fetch_certificates("blocked.com")

    assert "HTTP 403" in str(exc_info.value)


# --- 5. CtLogsProvider Tests ---

MOCK_CTLOGS_PAGE1 = {
    "rows": [
        {
            "id": "0000045306e2fcfbf57413af8d948ab08a664b849ee3",
            "match": "api.example.com",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-04-01T00:00:00Z",
            "serial_hex": "06e2fcfbf57413af8d948ab08a664b849ee3",
            "issuer": "Let's Encrypt",
            "key_algo": "ECDSA P-256",
            "san_count": 1,
        },
        {
            "id": "0000045306e2fcfbf57413af8d948ab08a664b849ee4",
            "match": "*.vpn.example.com",
            "not_before": "2025-02-01T00:00:00Z",
            "not_after": "2025-05-01T00:00:00Z",
            "serial_hex": "06e2fcfbf57413af8d948ab08a664b849ee4",
            "issuer": "DigiCert",
            "key_algo": "RSA 2048",
            "san_count": 1,
        },
    ],
    "has_next": True,
    "next_cursor": "cursor_page_2",
}

MOCK_CTLOGS_PAGE2 = {
    "rows": [
        {
            "id": "0000045306e2fcfbf57413af8d948ab08a664b849ee5",
            "match": "mail.example.com",
            "not_before": "2025-03-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "serial_hex": "06e2fcfbf57413af8d948ab08a664b849ee5",
            "issuer": "Sectigo",
            "key_algo": "RSA 2048",
            "san_count": 1,
        }
    ],
    "has_next": False,
    "next_cursor": None,
}


def test_ctlogs_provider_pagination_and_parsing_success():
    """Verify CtLogsProvider follows cursor pagination and maps rows into standard CT dictionaries."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_client = MagicMock()

    res_p1 = MagicMock()
    res_p1.status_code = 200
    res_p1.json.return_value = MOCK_CTLOGS_PAGE1

    res_p2 = MagicMock()
    res_p2.status_code = 200
    res_p2.json.return_value = MOCK_CTLOGS_PAGE2

    mock_client.get.side_effect = [res_p1, res_p2]

    provider = CtLogsProvider(client=mock_client, timeout=0.1, max_retries=2, api_key="test-api-key")
    records = provider.fetch_certificates("example.com")

    assert len(records) == 3
    assert records[0]["common_name"] == "api.example.com"
    assert records[0]["serial_number"] == "06e2fcfbf57413af8d948ab08a664b849ee3"
    assert records[1]["common_name"] == "*.vpn.example.com"
    assert records[2]["common_name"] == "mail.example.com"
    assert mock_client.get.call_count == 2

    # Verify authorization header was passed
    call_headers = mock_client.get.call_args[1]["headers"]
    assert call_headers["Authorization"] == "Bearer test-api-key"


def test_ctlogs_provider_404_returns_empty_list():
    """Verify CtLogsProvider returns empty list on 404 response."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_client = MagicMock()
    res_404 = MagicMock()
    res_404.status_code = 404
    mock_client.get.return_value = res_404

    provider = CtLogsProvider(client=mock_client, timeout=0.1, max_retries=2)
    records = provider.fetch_certificates("empty-domain.com")
    assert records == []


def test_ctlogs_provider_retry_on_502_success():
    """Verify CtLogsProvider retries transient 502 error and succeeds on second attempt."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_client = MagicMock()

    res_502 = MagicMock()
    res_502.status_code = 502
    res_502.text = "Bad Gateway"

    res_200 = MagicMock()
    res_200.status_code = 200
    res_200.json.return_value = MOCK_CTLOGS_PAGE2

    mock_client.get.side_effect = [res_502, res_200]

    provider = CtLogsProvider(client=mock_client, timeout=0.1, max_retries=3)
    records = provider.fetch_certificates("example.com")

    assert len(records) == 1
    assert records[0]["common_name"] == "mail.example.com"
    assert mock_client.get.call_count == 2


def test_ctlogs_provider_exhaustion_raises_ct_provider_error():
    """Verify CtLogsProvider raises CTProviderError when all retries return 500/502."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_client = MagicMock()

    res_503 = MagicMock()
    res_503.status_code = 503
    res_503.text = "Service Unavailable"
    mock_client.get.return_value = res_503

    provider = CtLogsProvider(client=mock_client, timeout=0.1, max_retries=2)
    with pytest.raises(CTProviderError) as exc_info:
        provider.fetch_certificates("failing.com")

    assert "Certificate Transparency fallback provider unavailable" in str(exc_info.value)


# --- 6. Multi-Provider Fallback & Orchestration Tests ---

def test_ct_service_primary_success_skips_fallback():
    """Verify that when crt.sh succeeds, fallback provider is not called."""
    mock_primary = MagicMock(spec=CrtShProvider)
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.return_value = MOCK_CRT_SH_RAW_DATA

    mock_fallback = MagicMock()
    mock_fallback.name = "ctlogs.dev"

    service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
    result = service.discover("example.com")

    assert result.source == "crt.sh"
    assert result.provider_used == "crt.sh"
    assert result.fallback_used is False
    assert result.provider_attempts["crt.sh"] == "success"
    assert mock_fallback.fetch_certificates.call_count == 0
    assert len(result.hostnames) == 5


def test_ct_service_primary_502_triggers_fallback_success():
    """Verify that when crt.sh fails with HTTP 502, CTService seamlessly falls back to ctlogs.dev."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_primary = MagicMock(spec=CrtShProvider)
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("Certificate Transparency provider unavailable (HTTP 502)")

    mock_fallback = MagicMock(spec=CtLogsProvider)
    mock_fallback.name = "ctlogs.dev"
    mock_fallback.fetch_certificates.return_value = [
        {
            "id": "ct_fallback_1",
            "common_name": "app.example.com",
            "name_value": "app.example.com\n*.internal.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-04-01T00:00:00Z",
            "serial_number": "99887766",
        }
    ]

    service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
    result = service.discover("example.com")

    assert result.source == "ctlogs.dev"
    assert result.provider_used == "ctlogs.dev"
    assert result.fallback_used is True
    assert "HTTP 502" in result.provider_attempts["crt.sh"]
    assert result.provider_attempts["ctlogs.dev"] == "success"
    assert mock_primary.fetch_certificates.call_count == 1
    assert mock_fallback.fetch_certificates.call_count == 1

    expected_hosts = {"example.com", "app.example.com", "internal.example.com"}
    assert set(result.hostnames) == expected_hosts
    assert len(result.certificates) == 1
    assert result.certificates[0].serial_number == "99887766"


def test_ct_service_primary_timeout_triggers_fallback_success():
    """Verify that when crt.sh times out, fallback provider is executed successfully."""
    from backend.app.services.ct_service import CtLogsProvider
    mock_primary = MagicMock(spec=CrtShProvider)
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("Timeout connecting to crt.sh")

    mock_fallback = MagicMock(spec=CtLogsProvider)
    mock_fallback.name = "ctlogs.dev"
    mock_fallback.fetch_certificates.return_value = [
        {
            "id": "ct_fallback_2",
            "common_name": "portal.example.com",
            "name_value": "portal.example.com",
            "issuer_name": "DigiCert",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-06-01T00:00:00Z",
            "serial_number": "11223344",
        }
    ]

    service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
    result = service.discover("example.com")

    assert result.provider_used == "ctlogs.dev"
    assert result.fallback_used is True
    assert "portal.example.com" in result.hostnames


def test_ct_service_both_providers_fail_raises_ct_provider_error():
    """Verify that when both crt.sh and ctlogs.dev fail, CTService raises a unified descriptive error."""
    mock_primary = MagicMock(spec=CrtShProvider)
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("HTTP 502 from crt.sh")

    mock_fallback = MagicMock()
    mock_fallback.name = "ctlogs.dev"
    mock_fallback.fetch_certificates.side_effect = CTProviderError("HTTP 503 from ctlogs.dev")

    service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
    with pytest.raises(CTProviderError) as exc_info:
        service.discover("example.com")

    err_str = str(exc_info.value)
    assert "Certificate Transparency providers unavailable" in err_str
    assert "crt.sh" in err_str
    assert "ctlogs.dev" in err_str


def test_ct_service_fallback_disabled_raises_primary_error():
    """Verify that when fallback is disabled, primary failure immediately raises without calling fallback."""
    mock_primary = MagicMock(spec=CrtShProvider)
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("crt.sh down")

    mock_fallback = MagicMock()
    mock_fallback.name = "ctlogs.dev"

    service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback, fallback_enabled=False)
    with pytest.raises(CTProviderError) as exc_info:
        service.discover("example.com")

    assert "crt.sh down" in str(exc_info.value)
    assert mock_fallback.fetch_certificates.call_count == 0


def test_ct_discovery_endpoint_fallback_provenance_and_persistence():
    """
    Integration test for multi-provider fallback in FastAPI endpoint:
    - Simulates crt.sh failure
    - Verifies endpoint executes fallback to ctlogs.dev
    - Verifies response returns provider_used="ctlogs.dev", fallback_used=True, provider_attempts
    - Verifies database records (Subdomains, Assets, ScanRun) store discovery_source="ctlogs.dev"
    """
    headers = get_auth_headers("analyst_one")

    inv_res = client.post(
        "/api/investigations",
        json={"name": "Fallback Provenance Test", "target_domain": "fallback-test.com"},
        headers=headers,
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    mock_primary = MagicMock()
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("HTTP 502 from crt.sh")

    mock_fallback = MagicMock()
    mock_fallback.name = "ctlogs.dev"
    mock_fallback.fetch_certificates.return_value = [
        {
            "id": "ctlogs_rec_1",
            "common_name": "secure.fallback-test.com",
            "name_value": "secure.fallback-test.com\n*.dev.fallback-test.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-04-01T00:00:00Z",
            "serial_number": "77889900",
        }
    ]

    with patch("backend.app.api.investigations.CTService") as MockCTServiceClass:
        real_service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
        mock_instance = MagicMock()
        mock_instance.discover.side_effect = real_service.discover
        MockCTServiceClass.return_value = mock_instance

        res = client.post(f"/api/investigations/{inv_id}/discover/ct", headers=headers)

    assert res.status_code == 200
    data = res.json()

    assert data["source"] == "ctlogs.dev"
    assert data["provider_used"] == "ctlogs.dev"
    assert data["fallback_used"] is True
    assert "provider_attempts" in data
    assert "HTTP 502" in data["provider_attempts"]["crt.sh"]
    assert data["provider_attempts"]["ctlogs.dev"] == "success"
    assert "secure.fallback-test.com" in data["hostnames"]
    assert "dev.fallback-test.com" in data["hostnames"]
    assert "fallback provider" in data["note"].lower()

    # Verify database persistence with ctlogs.dev provenance
    with TestingSessionLocal() as db:
        scan_run = db.execute(select(ScanRun).where(ScanRun.investigation_id == uuid.UUID(inv_id))).scalar_one()
        assert scan_run.status == "completed"
        assert scan_run.summary["provider_used"] == "ctlogs.dev"
        assert scan_run.summary["fallback_used"] is True

        subdomains = db.execute(
            select(Subdomain).join(Asset, Subdomain.asset_id == Asset.id).where(Asset.investigation_id == uuid.UUID(inv_id))
        ).scalars().all()
        for sub in subdomains:
            assert sub.discovery_source == "ctlogs.dev"


def test_ct_discovery_endpoint_idempotent_rerun_with_fallback():
    """Verify that re-running CT discovery with fallback provider does not create duplicate assets or certificates."""
    headers = get_auth_headers("analyst_one")

    inv_res = client.post(
        "/api/investigations",
        json={"name": "Idempotent Fallback Test", "target_domain": "idempotent-test.com"},
        headers=headers,
    )
    inv_id = inv_res.json()["id"]

    mock_primary = MagicMock()
    mock_primary.name = "crt.sh"
    mock_primary.fetch_certificates.side_effect = CTProviderError("crt.sh down")

    mock_fallback = MagicMock()
    mock_fallback.name = "ctlogs.dev"
    mock_fallback.fetch_certificates.return_value = [
        {
            "id": "rec_1",
            "common_name": "app.idempotent-test.com",
            "name_value": "app.idempotent-test.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2025-01-01T00:00:00Z",
            "not_after": "2025-04-01T00:00:00Z",
            "serial_number": "55443322",
        }
    ]

    with patch("backend.app.api.investigations.CTService") as MockCTServiceClass:
        real_service = CTService(primary_provider=mock_primary, fallback_provider=mock_fallback)
        mock_instance = MagicMock()
        mock_instance.discover.side_effect = real_service.discover
        MockCTServiceClass.return_value = mock_instance

        # First run
        res1 = client.post(f"/api/investigations/{inv_id}/discover/ct", headers=headers)
        assert res1.status_code == 200

        # Second run (same data)
        res2 = client.post(f"/api/investigations/{inv_id}/discover/ct", headers=headers)
        assert res2.status_code == 200

    with TestingSessionLocal() as db:
        # Should have 2 assets total: root domain + app.idempotent-test.com
        assets = db.execute(select(Asset).where(Asset.investigation_id == uuid.UUID(inv_id))).scalars().all()
        assert len(assets) == 2

        # Should have exactly 2 scan runs
        scan_runs = db.execute(select(ScanRun).where(ScanRun.investigation_id == uuid.UUID(inv_id))).scalars().all()
        assert len(scan_runs) == 2
