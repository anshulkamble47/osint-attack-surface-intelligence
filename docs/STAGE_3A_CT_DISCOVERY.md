# Stage 3A: Investigation Management & Multi-Provider Certificate Transparency (CT) Discovery

## 1. Overview & Purpose

Stage 3A implements passive OSINT asset discovery for the **OSINT-Based Attack Surface Intelligence & Risk Analysis Platform**.

This milestone bridges authenticated analyst workflows with passive external reconnaissance by enabling:
1. Creation and authorization of target investigations with deterministic domain normalization.
2. High-resilience Certificate Transparency (CT) discovery utilizing a multi-provider failover architecture (`crt.sh` as primary, `ctlogs.dev` as secondary fallback).
3. Parsing, cleaning, and strict domain-boundary matching of discovered candidate hostnames and Subject Alternative Names (SANs).
4. Deterministic deduplication and database persistence of discovered asset candidates, certificates, and scan history.
5. Rich provenance tracking to record which provider supplied each observation (`provider_used`, `fallback_used`, `provider_attempts`).
6. Structured API responses and interactive dashboard UI feedback.

> [!IMPORTANT]
> **Fundamental Limitation Notice:** Hostnames and subdomains discovered via Certificate Transparency logs are **candidates only**. A historical certificate logged in CT does NOT prove that the host is currently active, routable, or reachable on the internet. All CT-discovered assets are recorded with `is_active = False` and `is_resolving = False` until active DNS resolution and reachability verification are conducted in **Stage 3B**.
> Furthermore, while multi-provider failover dramatically increases discovery reliability, the platform does not claim 100% uptime guarantees over upstream public third-party CT logs.

---

## 2. Multi-Provider CT Architecture & Workflow

```
                        Discover CT
                             │
                             ▼
                   Primary Provider: crt.sh
                   (Retry / Backoff / Jitter)
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
      [Success: 200]                   [Transient Error / 5xx / 429 / Timeout]
            │                                 │
            │                                 ▼
            │                      Fallback Provider: ctlogs.dev
            │                      (Bounded Pagination / Defensive Parse)
            │                                 │
            │                        ┌────────┴────────┐
            │                        ▼                 ▼
            │                  [Success: 200]    [Provider Unavailable]
            │                        │                 │
            └───────────┬────────────┘                 ▼
                        ▼                     Clean Controlled Error
             Unified CT Normalization
                        │
                        ▼
             Domain Boundary Validation
                        │
                        ▼
             Deterministic Deduplication
                        │
                        ▼
         Persistence (Assets, Certs, ScanRun)
                        │
                        ▼
             API Response with Provenance
```

---

## 3. Key Components & Implementation Details

### 3.1 Domain Utility (`backend/app/utils/domain.py`)
- **`normalize_domain(raw_input: str) -> str`**: Strips URL schemes, ports, URL paths, query parameters, trailing dots, and leading wildcard notations (`*.api.example.com` → `api.example.com`). Converts to lowercase FQDN format.
- **`is_valid_domain(domain: str) -> bool`**: Enforces RFC 1035 / 1123 domain syntax (1–63 chars per label, alphanumeric with hyphens, non-numeric valid TLDs). Explicitly rejects raw IP addresses and non-routable `.local` / `localhost` scopes.
- **`is_subdomain_of(candidate: str, target: str) -> bool`**: Enforces strict domain boundary security (`candidate == target` OR `candidate.endswith("." + target)`), preventing substring poisoning.

### 3.2 Provider Abstraction & Providers (`backend/app/services/ct_service.py`)
- **`BaseCTProvider` (Abstract Base Class)**:
  - Defines the interface contract: `name: str` and `fetch_certificates(domain: str) -> List[Dict[str, Any]]`.
  - Providers return normalized raw certificate observation dictionaries containing `issuer`, `serial_number`, `subject_cn`, `san_list`, `not_before`, `not_after`, `ct_log_id`, and `fingerprint_sha256`.
- **`CrtShProvider` (Primary Provider)**:
  - Queries `https://crt.sh/?q=%.{domain}&output=json` with bounded connect/read timeouts (default 15.0s).
  - Implements bounded exponential backoff retry logic with full jitter (retrying transient 429, 500, 502, 503, 504, 520–524, and timeout errors).
  - Employs automatic wildcard query (`%.{domain}`) with fallback to apex domain query (`{domain}`) if needed.
  - Treats HTTP 404 cleanly as an empty result set (valid domain with zero logged certificates).
- **`CtLogsProvider` (Fallback Provider)**:
  - Connects over HTTPS to `https://api.ctlogs.dev/v1/subdomains/{domain}`.
  - Implements bounded cursor-based pagination (max 5 pages / 500 records per discovery run) to prevent resource exhaustion.
  - Defensively parses JSON responses and handles missing or unexpected fields.
  - Supports optional API key header via `CTLOGS_API_KEY` environment setting (functions unauthenticated by default).
- **`CTService` (Failover Orchestrator & Deduplication Engine)**:
  - Coordinates primary provider execution and initiates fallback upon provider failure (transient HTTP errors, connection timeouts, or unrecoverable provider outages).
  - Enforces domain boundary filtering across all returned Common Names and SAN lists.
  - Generates deterministic SHA-256 digests `SHA256(issuer_name + serial_number)` to uniquely deduplicate certificate records across provider logs.
  - Populates provenance metadata (`provider_used`, `fallback_used`, `provider_attempts`).

---

## 4. Configuration & Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `CT_PRIMARY_PROVIDER` | string | `"crt.sh"` | Name of the primary CT provider. |
| `CT_FALLBACK_ENABLED` | boolean | `true` | Enables secondary CT fallback provider if primary fails. |
| `CT_PROVIDER_TIMEOUT_SECONDS` | float | `15.0` | Bounded HTTP request timeout for external CT calls. |
| `CTLOGS_API_KEY` | string | `""` | Optional API key for `ctlogs.dev` (bearer token). |

---

## 5. Database Persistence & Provenance

Observations from both primary and fallback providers utilize the same existing persistence layer:

| Entity | Field | Content |
| :--- | :--- | :--- |
| **Asset** | `source` | Provider name (e.g. `crt.sh` or `ctlogs.dev`) |
| **Subdomain** | `discovery_source` | Provider name (e.g. `crt.sh` or `ctlogs.dev`) |
| **ScanRun** | `summary` | JSON object containing `provider_used`, `fallback_used`, `provider_attempts`, `discovered_hostnames_count`, `certificates_count` |
| **Certificate** | `fingerprint_sha256` | Deterministic SHA-256 fingerprint for deduplication |

---

## 6. API Reference

### Run Certificate Transparency Discovery
- **`POST /api/investigations/{investigation_id}/discover/ct`**
- **Auth:** Bearer Token (Investigation Owner or Admin)
- **Response (`200 OK`):**
  ```json
  {
    "investigation_id": "1f30b215-72a3-4399-9a18-affcdc5a984e",
    "target_domain": "example.com",
    "scan_run_id": "550e8400-e29b-41d4-a716-446655440000",
    "source": "crt.sh",
    "provider_used": "crt.sh",
    "fallback_used": false,
    "provider_attempts": {
      "crt.sh": "succeeded (5 hostnames, 2 certs)"
    },
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
    "discovery_timestamp": "2026-10-02T14:30:00Z",
    "note": "Certificate Transparency discovery completed using crt.sh. Discovered hostnames are stored as candidate assets pending active DNS resolution."
  }
  ```

---

## 7. Security Controls & SSRF Safeguards

1. **Strict Target Validation:** Target domains are normalized and validated against strict RFC syntax before issuing any external HTTP queries.
2. **Hardcoded Upstream Endpoints:** Requests are dispatched exclusively to known, trusted provider endpoints (`crt.sh` and `api.ctlogs.dev`). No user-supplied URLs or redirect targets are fetched.
3. **Bounded Size & Stream Limits:** Responses are parsed with strict length and page limits to protect against memory exhaustion or denial of service.
4. **Credential Isolation:** API keys are injected solely via server-side environment variables and are never transmitted to the browser or leaked into client logs.
5. **Passive Reconnaissance Only:** CT discovery operates strictly out-of-band against append-only public transparency logs without sending network packets to target host systems.

---

## 8. Automated Testing

The test suite thoroughly covers provider retry, error conditions, failover transitions, deduplication, and persistence without relying on live network connectivity:

```powershell
backend\.venv\Scripts\python.exe -m pytest tests/test_ct_discovery.py -v
```

Key test scenarios:
- Primary provider `crt.sh` success (fallback not invoked).
- Primary transient failures (HTTP 502, 429, timeouts) seamlessly triggering fallback to `ctlogs.dev`.
- Both providers unavailable producing structured `502 Bad Gateway` error.
- Deduplication of identical hostnames and certificates across repeat runs.
- ScanRun isolation and provenance verification.
