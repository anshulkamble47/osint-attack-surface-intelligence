# Stage 3B: Active DNS Intelligence & Reachability Probing

## 1. Overview & Architecture

Stage 3B extends the passive reconnaissance initiated in Stage 3A (Certificate Transparency) by actively resolving candidate subdomains and probing live HTTP/HTTPS service endpoints.

```
                    +------------------------------------+
                    | Investigation Created (Stage 3A)   |
                    +------------------------------------+
                                      |
                                      v
                    +------------------------------------+
                    | Passive CT Discovery (Stage 3A)    |
                    | (Asset: is_active=False,           |
                    |  Subdomain: is_resolving=False)    |
                    +------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| STAGE 3B ACTIVE DISCOVERY PIPELINE                                            |
|                                                                               |
|   1. Candidate Enumeration:                                                   |
|      Query all candidate subdomains and domain assets in scope.               |
|                                                                               |
|   2. Active DNS Intelligence (DNSService):                                    |
|      Perform structured DNS resolution using dnspython for:                   |
|      - A, AAAA (Address records)                                              |
|      - CNAME (Canonical name aliases)                                         |
|      - MX, NS, TXT (Mail, nameserver, and domain verification records)         |
|      Handle NXDOMAIN, Timeout, NoNameservers gracefully.                      |
|                                                                               |
|   3. Candidate State Transition:                                              |
|      - Resolving: Subdomain.is_resolving = True, Asset.is_active = True       |
|      - Non-resolving: Subdomain.is_resolving = False, Asset.is_active = False |
|      - Preserve non-resolving candidates in DB (Never delete).                |
|      - Persist DNSRecord observations linked to scan_run_id.                  |
|                                                                               |
|   4. Controlled Reachability Probing (ReachabilityService):                   |
|      For DNS-resolving assets only, execute lightweight GET requests to:      |
|      - Port 443 (HTTPS)                                                       |
|      - Port 80 (HTTP)                                                         |
|      Extract HTTP status code, page title, final URL, response time.          |
|      Persist ServiceExposure observations linked to scan_run_id.              |
|                                                                               |
|   5. Scan Tracking & Summary:                                                 |
|      Finalize ScanRun with status='completed' and detailed metrics.           |
+-------------------------------------------------------------------------------+
```

---

## 2. DNS Resolution Flow (`DNSService`)

- **Implementation**: Utilizes `dnspython` (`dns.resolver.Resolver`) without shell subprocesses.
- **Record Types Supported**:
  - `A`: IPv4 host addresses.
  - `AAAA`: IPv6 host addresses.
  - `CNAME`: Canonical name aliases.
  - `MX`: Mail exchanger records and preferences.
  - `NS`: Authoritative name servers.
  - `TXT`: Text records (SPF, domain verification, etc.).
- **Timeout & Resilience Configuration**:
  - `timeout = 2.0s` (per query).
  - `lifetime = 3.0s` (total query lifecycle).
- **Error Handling**:
  - `NXDOMAIN`: Hostname does not exist. Sets `is_resolving = False`, `error = "NXDOMAIN"`, halts further record lookups for that hostname.
  - `NoAnswer`: Specific record type does not exist for the hostname; continues to next record type.
  - `Timeout`: Query timed out; logs warning, records error, continues processing remaining candidates.
  - `NoNameservers`: No reachable nameservers; handles gracefully without crashing discovery run.
  - `DNSException`: General DNS resolution errors caught safely.

---

## 3. Candidate State Transitions & Lifecycle

| Stage / Condition | `Asset.is_active` | `Subdomain.is_resolving` | Action / Persistence |
| :--- | :--- | :--- | :--- |
| **Stage 3A (CT Discovery)** | `False` | `False` | Created as passive candidate asset. |
| **Stage 3B (DNS Resolves)** | `True` | `True` | Transitioned to active. `DNSRecord` observations attached to current `ScanRun`. Proceed to reachability probe. |
| **Stage 3B (NXDOMAIN / Timeout)** | `False` | `False` | Retained as inactive candidate asset in DB. Never deleted. |

---

## 4. Controlled Reachability Probing (`ReachabilityService`)

- **Implementation**: Utilizes `httpx.Client` with streaming response handling, manual safe redirect validation, and bounded body limits.
- **Strategy**:
  1. Probe `https://<hostname>` (port 443, TCP).
  2. Probe `http://<hostname>` (port 80, TCP).
- **Configuration**:
  - `timeout = 3.0s`.
  - `max_redirects = 3` (manual redirect loop with strict destination validation).
  - `MAX_BODY_BYTES = 65536` (64 KB maximum response body buffer limit to prevent memory exhaustion).
  - `verify = False` (permissive SSL validation to detect active services with self-signed or staging certificates).
  - Custom user-agent header: `Mozilla/5.0 (compatible; AttackSurfaceOSINT/1.0; +https://github.com/osint-platform)`.
- **Collected Attributes**:
  - `port` (80 / 443), `protocol` ("tcp"), `service_name` ("http" / "https").
  - `http_status` (e.g., 200, 301, 302, 403, 500).
  - `page_title` (extracted from `<title>` tags in first 8KB of response body).
  - `response_time_ms` (round-trip latency in milliseconds).
  - `final_url` (after following safe redirects).

---

## 5. SSRF & Network Safety Controls

Stage 3B implements defense-in-depth protections to ensure the platform cannot be leveraged as an SSRF (Server-Side Request Forgery) proxy against internal infrastructure:

1. **Pre-Flight Resolved IP Validation (`is_public_ip`)**:
   - Python's standard-library `ipaddress` module inspects all discovered `A` (IPv4) and `AAAA` (IPv6) records before HTTP/HTTPS probing is initiated.
   - Probing is **strictly blocked and skipped** if the candidate hostname resolves exclusively to:
     - Loopback (`127.0.0.0/8`, `::1`).
     - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
     - Link-local & Cloud metadata (`169.254.0.0/16`, `fe80::/10`).
     - Multicast (`224.0.0.0/4`, `ff00::/8`), Reserved (`240.0.0.0/4`), or Unspecified (`0.0.0.0`, `::`).
   - **Observation Preservation**: DNS records for private addresses are still saved in `DNSRecord` with `scan_run_id` for intelligence records, but zero HTTP network requests are executed against internal endpoints.

2. **Controlled Manual Redirect Validation**:
   - Automatic redirect following (`follow_redirects=True`) is disabled.
   - Redirects (`301`, `302`, `303`, `307`, `308`) are evaluated in a manual loop up to `max_redirects = 3`.
   - Before requesting any redirect destination (`Location` header), the destination URL scheme (`http`/`https`) and target host/IP are resolved and validated with `is_public_ip()`.
   - Any redirect pointing to loopback, private IP, localhost, or `.local`/`.internal` domains is immediately aborted with `SSRF Redirect Blocked`.

3. **Bounded Streaming Response Ingestion**:
   - Uses streaming reads (`client.stream("GET", ...)`) reading chunks up to `MAX_BODY_BYTES = 64KB`.
   - The stream terminates immediately once the ceiling is reached, preventing giant file downloads or infinite gzip bombs from exhausting server RAM.
   - HTML title parsing searches only within the first 8KB snippet (`html_content[:8192]`).

---

## 5. API Endpoints

### `POST /api/investigations/{id}/resolve`
- **Authentication**: Required (`Bearer <JWT>` - Analyst or Admin).
- **Description**: Triggers active DNS resolution and HTTP/HTTPS reachability probing across all candidate subdomains of the investigation.
- **Response Structure**:
```json
{
  "investigation_id": "84883180-2a81-42cb-b1b7-d1a1b181e1e1",
  "scan_run_id": "71a7d65b-6cf2-4c28-bf38-51adfa1e1e1e",
  "target_domain": "example.com",
  "candidates_processed": 10,
  "resolved": 7,
  "not_resolved": 3,
  "reachable": 5,
  "unreachable": 2,
  "dns_records_discovered": 18,
  "services_discovered": 8,
  "results": [
    {
      "hostname": "api.example.com",
      "is_resolving": true,
      "is_reachable": true,
      "dns_records_count": 2,
      "services_count": 2,
      "dns_records": [ ... ],
      "service_exposures": [ ... ],
      "error": null
    }
  ],
  "completed_at": "2026-09-23T18:00:00Z",
  "note": "Active DNS records and HTTP/HTTPS reachability observations persisted."
}
```

### `GET /api/investigations/{id}/dns-records`
- **Authentication**: Required.
- **Description**: Returns all historical and current DNS resource records collected for subdomains under the specified investigation.

### `GET /api/investigations/{id}/services`
- **Authentication**: Required.
- **Description**: Returns all HTTP/HTTPS network service reachability observations for assets under the specified investigation.

---

## 6. Database Persistence & Scan Run Isolation

Stage 3B respects the Stage 1 database schema without requiring any schema migrations:
- `DNSRecord`: Associated with `subdomain_id` and `scan_run_id`.
- `ServiceExposure`: Associated with `asset_id` and `scan_run_id`.
- `Asset.last_scan_run_id`: Updated to reference the latest `ScanRun`.

### Scan History Independence
Running the resolution pipeline multiple times produces separate `ScanRun` rows (Run #1, Run #2). The observations from Run #1 are **never** overwritten or deleted; each `DNSRecord` and `ServiceExposure` maintains an explicit foreign key to its respective `ScanRun`.

---

## 7. Testing Strategy

All external network operations (DNS resolution and HTTP requests) are fully mocked during test execution:
1. **Unit Tests (`DNSService`)**:
   - Resolution of IPv4 `A` records.
   - Resolution of IPv6 `AAAA` records.
   - Canonical name `CNAME` aliasing.
   - Multi-record sets (`MX`, `NS`, `TXT`).
   - `NXDOMAIN` non-fatal error handling.
   - Resolver query timeout handling.
   - Resolver nameserver failure handling.
2. **Unit Tests (`ReachabilityService`)**:
   - Live HTTP/HTTPS status 200 response with title extraction.
   - Redirect handling with final URL recording.
   - Connection timeout resilience.
   - Network error and connection refused resilience.
3. **Integration Tests (`test_dns_reachability.py`)**:
   - End-to-end resolution workflow.
   - Candidate state transitions (`is_resolving` and `is_active`).
   - Scan history preservation across consecutive scans.
   - RBAC authorization and multi-tenant investigation isolation.
   - Query endpoints (`/dns-records`, `/services`).

---

## 8. Strict Scope Boundary Between Stage 3B and Stage 4+

| Capability | Stage 3B (Current) | Stage 4 (IP / ASN / RDAP) | Stage 5 (Tech Fingerprint / Security) |
| :--- | :--- | :--- | :--- |
| **DNS Resolution** | Supported (A, AAAA, CNAME, MX, NS, TXT) | - | - |
| **Candidate State** | Active vs Inactive candidate | - | - |
| **Basic HTTP/HTTPS Reachability** | Supported (ports 80, 443 status & title) | - | - |
| **IP / Geolocation / Reverse DNS** | **NOT IMPLEMENTED** | Implemented in Stage 4 | - |
| **ASN BGP Routing / Prefix** | **NOT IMPLEMENTED** | Implemented in Stage 4 | - |
| **RDAP / Whois Enrichment** | **NOT IMPLEMENTED** | Implemented in Stage 4 | - |
| **Wappalyzer / Tech Stack Fingerprinting** | **NOT IMPLEMENTED** | - | Implemented in Stage 5 |
| **HTTP Security Headers (HSTS, CSP, etc.)** | **NOT IMPLEMENTED** | - | Implemented in Stage 5 |
| **Port Scanning / Network Enumeration** | **PROHIBITED** | **PROHIBITED** | **PROHIBITED** |
