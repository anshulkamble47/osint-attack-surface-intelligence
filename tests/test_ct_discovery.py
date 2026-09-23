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
