# Stage 2: Backend Core Foundation & Authentication

## 1. Overview

Stage 2 implements the core authentication and role-based access control (RBAC) foundation for the **OSINT-Based Attack Surface Intelligence & Risk Analysis Platform**.

This layer provides:
- Secure, salted password hashing using **Bcrypt** (cost factor 12).
- Stateless session management using signed **JSON Web Tokens (JWT)** (HMAC-SHA256).
- Role-based authorization dependencies supporting `admin`, `analyst`, and `auditor` roles.
- Safe serialization using **Pydantic v2** ensuring passwords and hashes are never exposed in API payloads.

---

## 2. Authentication API Endpoints

| Method | Endpoint | Access | Description | Status Code |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Register new analyst user account with hashed password | `201 Created` |
| `POST` | `/api/auth/login` | Public | Authenticate via username or email and obtain JWT access token | `200 OK` |
| `GET` | `/api/auth/me` | Authenticated | Retrieve current user profile | `200 OK` |

---

## 3. Cryptographic Security & Password Hashing

- **Algorithm:** `bcrypt` with salt generation (12 work factor rounds).
- **Implementation:** [backend/app/core/security.py](file:///e:/Ware/OSINT%20Dashboard/backend/app/core/security.py)
- **Functions:**
  - `hash_password(password: str) -> str`: Produces `$2b$12$...` hashes. Plaintext passwords are never logged or stored.
  - `verify_password(plain_password: str, hashed_password: str) -> bool`: Constant-time hash verification.

---

## 4. JWT Token Lifecycle & Structure

- **Signing Key:** Configured via `JWT_SECRET` in `.env`.
- **Algorithm:** `HS256` (HMAC-SHA256).
- **Default Expiration:** `ACCESS_TOKEN_EXPIRE_MINUTES=1440` (24 hours).
- **Claims Payload:**
  ```json
  {
    "sub": "e6518714-113e-4f2f-9a87-28c1e6b965df",
    "username": "analyst_alice",
    "role": "analyst",
    "iat": 1758647788,
    "exp": 1758734188
  }
  ```

---

## 5. Role-Based Access Control (RBAC)

The platform supports 3 defined roles:
- **`admin`**: Full platform management, user administration, scan configuration overrides.
- **`analyst`**: Core operational role for creating investigations, triggering scans, reviewing findings, and generating reports.
- **`auditor`**: Read-only compliance and timeline review role.

### Reusable Dependency Usage:
```python
from fastapi import Depends
from backend.app.api.deps import require_role
from backend.app.models.user import User

# Protect route for admin only
@router.post("/admin-action")
def admin_action(current_user: User = Depends(require_role("admin"))):
    ...

# Protect route for analyst or admin
@router.post("/investigations")
def start_investigation(current_user: User = Depends(require_role("analyst", "admin"))):
    ...
```

If an analyst attempts to access an admin-only endpoint, FastAPI returns `HTTP 403 Forbidden`:
```json
{
  "detail": "Insufficient permissions. Action requires one of the following roles: ['admin']. Your current role is: 'analyst'."
}
```

---

## 6. Environment Configuration

The following variables in `.env` govern authentication:
```bash
# Security & JWT Configuration
JWT_SECRET=development_jwt_secret_replace_in_production_environment_random_key_64chars
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
```

---

## 7. Local Testing Guide

### 1. Register a New User
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@example.com",
    "username": "alice",
    "password": "SecurePassword123!",
    "full_name": "Alice Analyst"
  }'
```
*Note: Public registration automatically and safely assigns the default `"analyst"` role. Supplying a `role` field from the client is rejected.*

### 2. Log in and Obtain Token
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username_or_email": "alice",
    "password": "SecurePassword123!"
  }'
```

### 3. Access Protected Profile (`/me`)
```bash
curl http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### 4. Run Automated Test Suite
```powershell
backend\.venv\Scripts\python.exe -m pytest tests/test_auth.py -v
```
