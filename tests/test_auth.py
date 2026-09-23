"""Comprehensive tests for Stage 2 User Authentication, JWT security, and Role-based Access Control."""

from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database.base import Base
from backend.app.database.connection import get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from backend.app.api.deps import require_role
from fastapi import Depends, APIRouter
from tests.conftest import TestingSessionLocal

# Role-protected test routes attached for verifying require_role dependency
test_role_router = APIRouter(prefix="/api/test-rbac", tags=["Testing RBAC"])


@test_role_router.get("/admin-only")
def admin_only_route(current_user: User = Depends(require_role("admin"))):
    return {"message": "Admin access granted", "username": current_user.username}


@test_role_router.get("/analyst-or-admin")
def analyst_route(current_user: User = Depends(require_role("analyst", "admin"))):
    return {"message": "Analyst access granted", "username": current_user.username}


@test_role_router.get("/auditor-only")
def auditor_only_route(current_user: User = Depends(require_role("auditor"))):
    return {"message": "Auditor access granted", "username": current_user.username}


app.include_router(test_role_router)

client = TestClient(app)


# --- 1. Password Hashing & Verification Tests ---

def test_password_hashing_security():
    """Verify password hashing produces bcrypt hashes and never matches plaintext."""
    plain = "SuperSecretPassword123!"
    hashed = hash_password(plain)

    assert hashed != plain
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


# --- 2. Registration Tests ---

def test_successful_user_registration():
    """Verify that a new analyst user can register successfully without specifying a role."""
    payload = {
        "email": "analyst.alice@security.local",
        "username": "alice_analyst",
        "password": "SecurePassword2026!",
        "full_name": "Alice Analyst",
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert data["email"] == "analyst.alice@security.local"
    assert data["username"] == "alice_analyst"
    assert data["full_name"] == "Alice Analyst"
    assert data["role"] == "analyst"
    assert data["is_active"] is True
    assert "id" in data

    # Security check: passwords and hashes must NEVER appear in response
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify directly in DB that password is encrypted
    with TestingSessionLocal() as db:
        user_in_db = db.execute(
            select(User).where(User.username == "alice_analyst")
        ).scalar_one()
        assert user_in_db.hashed_password != "SecurePassword2026!"
        assert verify_password("SecurePassword2026!", user_in_db.hashed_password) is True
        assert user_in_db.role == "analyst"


def test_registration_cannot_specify_or_escalate_role():
    """
    SECURITY TEST: Verify that public registration strictly forbids clients
    from supplying a 'role' parameter (e.g. attempting to create an admin account).
    """
    # 1. Attempt privilege escalation to admin
    admin_escalation_payload = {
        "email": "malicious.admin@security.local",
        "username": "malicious_admin",
        "password": "AdminPassword123!",
        "role": "admin",
    }
    res_admin = client.post("/api/auth/register", json=admin_escalation_payload)
    assert res_admin.status_code == 422  # Extra fields are forbidden by Pydantic schema

    # 2. Attempt role specification to auditor
    auditor_payload = {
        "email": "auditor.attempt@security.local",
        "username": "auditor_attempt",
        "password": "AuditorPassword123!",
        "role": "auditor",
    }
    res_auditor = client.post("/api/auth/register", json=auditor_payload)
    assert res_auditor.status_code == 422

    # 3. Verify in database that neither user was created
    with TestingSessionLocal() as db:
        user_admin = db.execute(
            select(User).where(User.username == "malicious_admin")
        ).scalar_one_or_none()
        assert user_admin is None

        user_auditor = db.execute(
            select(User).where(User.username == "auditor_attempt")
        ).scalar_one_or_none()
        assert user_auditor is None


def test_registration_always_assigns_default_analyst_role():
    """Verify registration always creates users with safe server-side default 'analyst' role."""
    payload = {
        "email": "default.role@security.local",
        "username": "default_role_user",
        "password": "SafePassword123!",
        "full_name": "Default Role Test",
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["role"] == "analyst"

    with TestingSessionLocal() as db:
        user = db.execute(
            select(User).where(User.username == "default_role_user")
        ).scalar_one()
        assert user.role == "analyst"


def test_duplicate_registration_rejection():
    """Verify rejection of duplicate email or username."""
    # Duplicate email
    dup_email_payload = {
        "email": "analyst.alice@security.local",
        "username": "another_alice",
        "password": "Password12345!",
    }
    res1 = client.post("/api/auth/register", json=dup_email_payload)
    assert res1.status_code == 409
    assert "email" in res1.json()["detail"].lower()

    # Duplicate username
    dup_user_payload = {
        "email": "alice.new@security.local",
        "username": "alice_analyst",
        "password": "Password12345!",
    }
    res2 = client.post("/api/auth/register", json=dup_user_payload)
    assert res2.status_code == 409
    assert "username" in res2.json()["detail"].lower()


def test_registration_validation_errors():
    """Verify validation on invalid emails, short usernames, and weak passwords."""
    # Invalid email
    res1 = client.post("/api/auth/register", json={
        "email": "not-an-email",
        "username": "valid_user",
        "password": "Password123!",
    })
    assert res1.status_code == 422

    # Password too short (< 8 chars)
    res2 = client.post("/api/auth/register", json={
        "email": "user@security.local",
        "username": "valid_user",
        "password": "123",
    })
    assert res2.status_code == 422

    # Username with invalid characters
    res3 = client.post("/api/auth/register", json={
        "email": "user@security.local",
        "username": "user with spaces!",
        "password": "Password123!",
    })
    assert res3.status_code == 422


# --- 3. Login & Token Generation Tests ---

def test_successful_login_with_username_and_email():
    """Verify login with username or email returns JWT access token and user info."""
    # Login with username
    res1 = client.post("/api/auth/login", json={
        "username_or_email": "alice_analyst",
        "password": "SecurePassword2026!",
    })
    assert res1.status_code == 200
    data1 = res1.json()
    assert "access_token" in data1
    assert data1["token_type"] == "bearer"
    assert data1["expires_in_seconds"] > 0
    assert data1["user"]["username"] == "alice_analyst"
    assert "hashed_password" not in data1["user"]

    # Login with email
    res2 = client.post("/api/auth/login", json={
        "username_or_email": "analyst.alice@security.local",
        "password": "SecurePassword2026!",
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert "access_token" in data2
    assert data2["user"]["email"] == "analyst.alice@security.local"


def test_invalid_login_rejection():
    """Verify invalid password or non-existent username returns 401 Unauthorized."""
    # Wrong password
    res1 = client.post("/api/auth/login", json={
        "username_or_email": "alice_analyst",
        "password": "IncorrectPassword999!",
    })
    assert res1.status_code == 401
    assert res1.headers.get("WWW-Authenticate") == "Bearer"

    # Non-existent user
    res2 = client.post("/api/auth/login", json={
        "username_or_email": "ghost_user_does_not_exist",
        "password": "AnyPassword123!",
    })
    assert res2.status_code == 401


# --- 4. Protected /api/auth/me Endpoint Tests ---

def test_get_current_user_profile():
    """Verify /api/auth/me returns authenticated user details when Bearer token is provided."""
    # Log in to get valid token
    login_res = client.post("/api/auth/login", json={
        "username_or_email": "alice_analyst",
        "password": "SecurePassword2026!",
    })
    token = login_res.json()["access_token"]

    # Access /api/auth/me with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    user_data = me_res.json()
    assert user_data["username"] == "alice_analyst"
    assert user_data["email"] == "analyst.alice@security.local"
    assert "password" not in user_data
    assert "hashed_password" not in user_data


def test_unauthenticated_access_rejection():
    """Verify accessing /api/auth/me without token returns 401 Unauthorized."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_invalid_and_expired_jwt_rejection():
    """Verify malformed and expired JWTs are rejected with 401 Unauthorized."""
    # Malformed token
    res1 = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.token.payload"})
    assert res1.status_code == 401

    # Expired token
    expired_token = create_access_token(
        data={"sub": "00000000-0000-0000-0000-000000000001", "username": "expired_user"},
        expires_delta=timedelta(seconds=-60),
    )
    res2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res2.status_code == 401
    assert "expired" in res2.json()["detail"].lower()


# --- 5. Role-Based Access Control (RBAC) Tests ---

def test_role_based_access_control():
    """
    Verify require_role dependency enforces authorization:
    - admin can access admin routes
    - analyst can access analyst routes but is rejected on admin routes (403 Forbidden)
    - auditor can access auditor routes
    """
    # 1. Seed Admin user directly in database (role assignment is strictly administrative)
    with TestingSessionLocal() as db:
        admin_user = User(
            email="admin@security.local",
            username="root_admin",
            hashed_password=hash_password("AdminPassword2026!"),
            full_name="Root Administrator",
            role="admin",
            is_active=True,
        )
        auditor_user = User(
            email="auditor@security.local",
            username="compliance_auditor",
            hashed_password=hash_password("AuditorPassword2026!"),
            full_name="Compliance Auditor",
            role="auditor",
            is_active=True,
        )
        db.add(admin_user)
        db.add(auditor_user)
        db.commit()

    # Authenticate Admin
    admin_login = client.post("/api/auth/login", json={
        "username_or_email": "root_admin",
        "password": "AdminPassword2026!",
    })
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Authenticate Auditor
    auditor_login = client.post("/api/auth/login", json={
        "username_or_email": "compliance_auditor",
        "password": "AuditorPassword2026!",
    })
    auditor_token = auditor_login.json()["access_token"]
    auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

    # Authenticate Analyst (alice)
    alice_login = client.post("/api/auth/login", json={
        "username_or_email": "alice_analyst",
        "password": "SecurePassword2026!",
    })
    analyst_headers = {"Authorization": f"Bearer {alice_login.json()['access_token']}"}

    # Admin tests: can access admin and analyst routes, cannot access auditor-only
    assert client.get("/api/test-rbac/admin-only", headers=admin_headers).status_code == 200
    assert client.get("/api/test-rbac/analyst-or-admin", headers=admin_headers).status_code == 200
    assert client.get("/api/test-rbac/auditor-only", headers=admin_headers).status_code == 403

    # Analyst tests: can access analyst routes, forbidden from admin routes
    assert client.get("/api/test-rbac/analyst-or-admin", headers=analyst_headers).status_code == 200
    res_admin_denied = client.get("/api/test-rbac/admin-only", headers=analyst_headers)
    assert res_admin_denied.status_code == 403
    assert "insufficient permissions" in res_admin_denied.json()["detail"].lower()

    # Auditor tests: can access auditor routes, forbidden from admin and analyst routes
    assert client.get("/api/test-rbac/auditor-only", headers=auditor_headers).status_code == 200
    assert client.get("/api/test-rbac/admin-only", headers=auditor_headers).status_code == 403
    assert client.get("/api/test-rbac/analyst-or-admin", headers=auditor_headers).status_code == 403


# --- 6. JWT Configuration & Security Hardening Tests ---

def test_jwt_configuration_and_production_protection():
    """
    Verify that JWT settings are properly configured from environment and
    production environments reject weak/default secret keys.
    """
    from backend.app.core.config import Settings, settings

    # 1. Verify current settings have valid algorithm and configurable expiration
    assert settings.JWT_ALGORITHM == "HS256"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert len(settings.JWT_SECRET) >= 32

    # 2. Verify production mode rejects insecure fallback secret
    with pytest.raises(Exception) as exc_info:
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET="development_jwt_secret_replace_in_production_environment_random_key_64chars",
            _env_file=None,
        )
    assert "JWT_SECRET must be explicitly set" in str(exc_info.value)

    # 3. Verify production mode accepts strong custom secret
    prod_settings = Settings(
        ENVIRONMENT="production",
        JWT_SECRET="c7929a738546b3f7f02b37803e08f515e0169d273a3df69d95f001e389d46059",
        _env_file=None,
    )
    assert prod_settings.JWT_SECRET == "c7929a738546b3f7f02b37803e08f515e0169d273a3df69d95f001e389d46059"
