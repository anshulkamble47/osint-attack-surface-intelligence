# Stage 3A: Investigation Management & Certificate Transparency (CT) Discovery

## 1. Overview & Purpose

Stage 3A implements the first passive OSINT discovery capability for the **OSINT-Based Attack Surface Intelligence & Risk Analysis Platform**.

This milestone bridges authenticated analyst workflows with passive external reconnaissance by enabling:
1. Creation and authorization of target investigations with deterministic domain normalization.
2. Passive querying of public Certificate Transparency (CT) logs (`crt.sh`).
3. Parsing, cleaning, and strict domain-boundary matching of discovered candidate hostnames and Subject Alternative Names (SANs).
4. Deterministic deduplication and database persistence of discovered asset candidates, certificates, and scan history.
5. Structured API responses and an interactive assessment dashboard.

> [!IMPORTANT]
> **Fundamental Limitation Notice:** Hostnames and subdomains discovered via Certificate Transparency logs are **candidates only**. A historical certificate logged in CT does NOT prove that the host is currently active, routable, or reachable on the internet. All CT-discovered assets are recorded with `is_active = False` and `is_resolving = False` until active DNS resolution and reachability verification are conducted in **Stage 3B**.

---

## 2. End-to-End Investigation & CT Workflow

```
Authenticated Analyst
        ↓
POST /api/investigations (target_domain="https://Example.COM:443/audit")
        ↓
Domain Normalization & Validation ("example.com")
        ↓
Create Target & Investigation Entities (status="pending")
        ↓
POST /api/investigations/{id}/discover/ct
        ↓
Create Point-in-Time ScanRun #N (status="running")
        ↓
CrtShProvider (Passive HTTPS Query to crt.sh JSON API)
        ↓
Extract Common Names & Subject Alternative Names (SANs)
        ↓
Clean & Normalize Hostnames (strip wildcards, trailing dots, lowercasing)
        ↓
Domain Boundary Validation (Filter out unrelated third-party domains & subdomains)
        ↓
Deduplicate Hostnames & Certificates
        ↓
Persist to DB (Assets, Subdomains, Certificates, subdomain_certificates)
        ↓
Update ScanRun (status="completed", summary stats) & Investigation (status="active")
        ↓
Return Structured CTDiscoveryResponse
```

---

## 3. Architecture & Key Components

### 3.1 Domain Utility (`backend/app/utils/domain.py`)
- **`normalize_domain(raw_input: str) -> str`**:
  - Strips URL schemes (`http://`, `https://`), network ports (`:443`), paths (`/test`), query parameters, trailing dots, and leading wildcard notations (`*.api.example.com` → `api.example.com`).
  - Converts all output to lowercase FQDN format.
- **`is_valid_domain(domain: str) -> bool`**:
  - Enforces RFC 1035 / 1123 domain syntax (1–63 chars per label, alphanumeric with hyphens, non-numeric valid TLDs).
  - Explicitly rejects raw IP addresses and non-routable `.local` / `localhost` scopes.
- **`is_subdomain_of(candidate: str, target: str) -> bool`**:
  - Enforces strict domain boundary security.
  - Matches if `candidate == target` OR `candidate.endswith("." + target)`.
  - Prevents substring poisoning (e.g., `notexample.com` or `my-example.com` are strictly excluded for target `example.com`).

### 3.2 Certificate Transparency Service (`backend/app/services/ct_service.py`)
- **`CrtShProvider`**:
  - Performs low-impact, passive queries against `https://crt.sh/?q=%.{domain}&output=json`.
  - Configured with explicit timeouts (12.0s), custom `User-Agent`, and graceful handling of upstream HTTP 429/502/503/504 errors and malformed responses.
- **`CTService`**:
  - Parses certificate logs, extracts SAN lists, normalizes hostnames, and enforces boundary filtering.
  - **Deterministic Certificate Identifier:** Because public CT log JSON endpoints return high-level certificate metadata rather than raw X.509 DER byte streams, the system computes a deterministic SHA-256 hash of `(issuer_name + serial_number)` to uniquely identify and deduplicate certificate records across log entries. This avoids duplicate records while conforming to the fixed 64-character database schema. True cryptographic SHA-256 digests of raw DER bytes can be captured during active TLS endpoint scanning in future stages.
  - Merges SAN lists across duplicate certificate observations.

---

## 4. Database Persistence Model (Reusing Stage 1 Schema)

Stage 3A maps observations directly to the Stage 1 database models without requiring any schema migrations:

| Entity | Model Class | Fields Populated | Status / Flags |
| :--- | :--- | :--- | :--- |
| **Target** | `Target` | `primary_domain`, `name`, `organization`, `is_authorized` | Authorized root target scope |
| **Investigation** | `Investigation` | `reference_code`, `target_id`, `title`, `created_by_id`, `status` | Initialized as `pending`, transitions to `active` upon discovery |
| **Scan Run** | `ScanRun` | `run_number`, `investigation_id`, `total_discovered_assets`, `summary` | Tracks point-in-time CT discovery execution |
| **Asset** | `Asset` | `target_id`, `investigation_id`, `asset_type`, `value`, `source`, `confidence` | Discovered subdomains flagged with `is_active = False` |
| **Subdomain** | `Subdomain` | `asset_id`, `domain_id`, `subdomain_name`, `discovery_source` | Flagged with `is_resolving = False` (unverified candidate) |
| **Certificate** | `Certificate` | `fingerprint_sha256`, `subject_cn`, `issuer`, `valid_from`, `valid_to`, `san_list`, `is_expired` | TLS certificate metadata & expiration state |
| **Association** | `subdomain_certificates` | `subdomain_id`, `certificate_id`, `scan_run_id`, `observed_at` | M:N historical link between subdomains and certs |

---

## 5. API Reference

### 1. Create Investigation
- **`POST /api/investigations`**
- **Auth:** Bearer Token (Analyst or Admin)
- **Request Body:**
  ```json
  {
    "name": "Acme External Surface Review",
    "target_domain": "https://example.com/",
    "organization": "Acme Corp"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "id": "1f30b215-72a3-4399-9a18-affcdc5a984e",
    "reference_code": "INV-20260923-001-A1B2",
    "target_id": "845c7b39-2a94-4f51-b845-8f6a96bc4391",
    "target_domain": "example.com",
    "title": "Acme External Surface Review",
    "status": "pending",
    "created_by_id": "11111111-1111-1111-1111-111111111111",
    "created_at": "2026-09-23T17:40:00Z"
  }
  ```

### 2. List Investigations
- **`GET /api/investigations`**
- **Auth:** Bearer Token (Returns own investigations for analysts, all for admins)
- **Response (`200 OK`):** List of `InvestigationResponse` objects.

### 3. Run Certificate Transparency Discovery
- **`POST /api/investigations/{investigation_id}/discover/ct`**
- **Auth:** Bearer Token (Investigation Owner or Admin)
- **Response (`200 OK`):**
  ```json
  {
    "investigation_id": "1f30b215-72a3-4399-9a18-affcdc5a984e",
    "target_domain": "example.com",
    "scan_run_id": "550e8400-e29b-41d4-a716-446655440000",
    "source": "crt.sh",
    "hostname_count": 5,
    "certificate_count": 2,
    "hostnames": [
      "api.example.com",
      "auth.example.com",
      "example.com",
      "legacy-vpn.example.com",
      "mail.example.com"
    ],
    "certificates": [
      {
        "fingerprint_sha256": "da7a4247632bc8c66f96323e987ac45b7873f4918cf51ca5a407e7958daacde4",
        "subject_cn": "example.com",
        "issuer": "C=US, O=Let's Encrypt, CN=R3",
        "san_list": ["api.example.com", "auth.example.com", "example.com"],
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_to": "2025-04-01T00:00:00Z",
        "is_expired": true,
        "ct_log_id": "1001"
      }
    ],
    "discovery_timestamp": "2026-09-23T17:41:00Z",
    "note": "Hostnames are candidate assets discovered from CT logs. Active DNS reachability validation occurs in Stage 3B."
  }
  ```

### 4. List Investigation Assets
- **`GET /api/investigations/{investigation_id}/assets`**
- **Auth:** Bearer Token (Investigation Owner or Admin)
- **Response (`200 OK`):** List of discovered asset items.

---

## 6. Error Handling & HTTP Status Codes

- `400 Bad Request` / `422 Unprocessable Entity`: Invalid target domain format (spaces, IP addresses, missing labels).
- `401 Unauthorized`: Missing or invalid Bearer JWT token.
- `403 Forbidden`: Non-admin analyst attempting to access another analyst's private investigation.
- `404 Not Found`: Investigation ID not found.
- `502 Bad Gateway`: Upstream CT log provider timeout or HTTP error (returns structured error message and records `ScanRun` as `failed` without crashing the application).

---

## 7. Automated Test Suite

All tests are deterministic and do not depend on external network/crt.sh uptime:
- **Unit Tests:** Domain normalization, subdomain boundary checks, certificate fingerprinting and SAN deduplication.
- **Integration Tests:** JWT authorization enforcement, cross-user isolation, mocked CT discovery pipeline, database persistence, and candidate asset flag verification.

Command to execute full suite:
```powershell
backend\.venv\Scripts\python.exe -m pytest tests/ -v
```
