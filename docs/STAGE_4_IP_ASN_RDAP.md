# Stage 4: IP / ASN / RDAP Intelligence & Historical Scan Isolation

## 1. Overview & Architecture

Stage 4 builds the **IP intelligence layer** that enriches IP addresses discovered during Stage 3B active DNS resolution (`A` and `AAAA` records).

The Stage 4 architecture separates reusable IP entities from point-in-time scan observations, implements authoritative IANA RDAP bootstrap discovery, and enforces strict pre-connection DNS SSRF protections:

```
Existing Investigation DNS Observations
                  │
                  ▼
        Extract A / AAAA Records
                  │
                  ▼
  IP Validation & Normalization (ipaddress)
        ├── Reject Invalid IP Values
        ├── Deduplicate Across Subdomains
        └── Classify Public vs Non-Public
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
[Non-Public / Private]  [Public IP Addresses]
(Skipped from Queries)       │
                             ├──► ASN Intelligence (Team Cymru DNS TXT Provider)
                             │     ├── ASN Number & Name
                             │     └── Allocated Network Prefix & Country
                             │
                             └──► RDAP Intelligence (IANA Bootstrap Discovery + Pre-DNS SSRF Guard)
                                   ├── Authoritative RIR Base URL (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
                                   ├── Pre-Connection DNS Resolution & Public IP Verification
                                   ├── Network Name, Handle, CIDR, Range, Organization, Country
                                   └── Registration & Update Timestamps
                                       │
                                       ▼
                       Persistence & Historical Scan Isolation
                        ├── IPAddress Entity (ip_addresses table: Reusable Identity)
                        ├── ASN Entity (asns table: Reusable Identity)
                        ├── IPObservation Entity (ip_observations table: Point-in-Time Scan Record)
                        ├── Cryptographic Evidence (evidence table with SHA-256)
                        └── Point-in-Time ScanRun (scan_runs table with summary metrics)
```

---

## 2. Historical IP / ASN Scan Isolation (`IPObservation`)

### Conceptual Model
- **`IPAddress` (Entity/Singleton):** Represents the unique IP identity (`ip_address` is globally unique). Stores current/reusable metadata (such as latest known country, organization, active status, latest ASN pointer).
- **`IPObservation` (Point-in-Time Fact):** Represents the observed state of an IP and its associated Autonomous System during an individual `ScanRun`:

```
               ScanRun
                  │
                  ▼
            IPObservation
             ↙         ↘
       IPAddress       ASN
```

### Table Schema & Constraints
```sql
CREATE TABLE ip_observations (
    id UUID PRIMARY KEY,
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip_address_id UUID NOT NULL REFERENCES ip_addresses(id) ON DELETE CASCADE,
    asn_id UUID REFERENCES asns(id) ON DELETE SET NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_ip_observations_scan_run_ip UNIQUE (scan_run_id, ip_address_id)
);
```

### Historical Reconstruction Example
Suppose an organization migrates hosting providers or experiences a BGP route shift between scans:

- **Scan A (`ScanRun #1`):**
  - Discovered IP: `1.2.3.4`
  - ASN Lookup: `ASN 100 (AS100-OLD-ISP)`
  - Database Records Created:
    - `IPAddress(ip_address="1.2.3.4", asn_id=ASN_100.id)`
    - `IPObservation(scan_run_id=Run1.id, ip_address_id=1.2.3.4, asn_id=ASN_100.id)`

- **Scan B (`ScanRun #2`):**
  - Discovered IP: `1.2.3.4`
  - ASN Lookup: `ASN 200 (AS200-NEW-ISP)`
  - Database Records Created/Updated:
    - `IPAddress(ip_address="1.2.3.4", asn_id=ASN_200.id)` (current pointer updated)
    - `IPObservation(scan_run_id=Run2.id, ip_address_id=1.2.3.4, asn_id=ASN_200.id)`

**Outcome:**
Both observations remain queryable and immutable. An analyst auditing Scan #1 will always see that `1.2.3.4` belonged to `ASN 100` at the time of Scan #1, while Scan #2 accurately reflects `ASN 200`.

---

## 3. Authoritative IANA RDAP Bootstrap (`RDAPBootstrap`)

Located in [`backend/app/services/rdap_service.py`](file:///e:/Ware/OSINT%20Dashboard/backend/app/services/rdap_service.py):

Rather than hardcoding ARIN (`rdap.arin.net`) and relying on external redirects, the platform determines the authoritative Regional Internet Registry (RIR) using IANA IPv4 and IPv6 RDAP bootstrap prefix registries (RFC 7484 / RFC 9224):

1. **IPv4 Bootstrap Discovery:**
   - Evaluates the target IP against canonical /8 allocations:
     - **AFRINIC:** `41.0.0.0/8`, `102.0.0.0/8`, `105.0.0.0/8`, `154.0.0.0/8`, `196.0.0.0/8`, `197.0.0.0/8` -> `https://rdap.afrinic.net/rdap/`
     - **APNIC:** `1.0.0.0/8`, `14.0.0.0/8`, `27.0.0.0/8`, `36.0.0.0/8`, `42.0.0.0/8`, `101.0.0.0/8`, `103.0.0.0/8`, `202.0.0.0/8`, etc. -> `https://rdap.apnic.net/`
     - **LACNIC:** `177.0.0.0/8`, `179.0.0.0/8`, `181.0.0.0/8`, `186.0.0.0/8`, `200.0.0.0/8`, `201.0.0.0/8`, etc. -> `https://rdap.lacnic.net/rdap/`
     - **RIPE NCC:** `2.0.0.0/8`, `5.0.0.0/8`, `25.0.0.0/8`, `31.0.0.0/8`, `77.0.0.0/8`, `80.0.0.0/8`, `93.0.0.0/8`, `193.0.0.0/8`, `212.0.0.0/8`, etc. -> `https://rdap.db.ripe.net/`
     - **ARIN:** `3.0.0.0/8`, `8.0.0.0/8`, `12.0.0.0/8`, `24.0.0.0/8`, `64.0.0.0/8`, `96.0.0.0/8`, `128.0.0.0/8`, `208.0.0.0/8`, etc. -> `https://rdap.arin.net/registry/`

2. **IPv6 Bootstrap Discovery:**
   - Evaluates IPv6 address prefixes against major RIR allocations:
     - **AFRINIC:** `2001:4200::/23`, `2001:4300::/24`, `2c00::/12` -> `https://rdap.afrinic.net/rdap/`
     - **APNIC:** `2001:200::/23`, `2001:800::/23`, `2400::/12` -> `https://rdap.apnic.net/`
     - **LACNIC:** `2001:1200::/23`, `2800::/12` -> `https://rdap.lacnic.net/rdap/`
     - **RIPE NCC:** `2001:600::/23`, `2001:800::/22`, `2a00::/12` -> `https://rdap.db.ripe.net/`
     - **ARIN:** `2001:4800::/23`, `2600::/12`, `2606::/16`, `2607::/16` -> `https://rdap.arin.net/registry/`

3. **Performance & Dynamic Loading:**
   - Pre-compiled in-memory radix/network lookups ensure zero overhead and eliminate recurring bootstrap network round-trips.
   - Dynamic loading (`load_bootstrap_registry`) allows runtime updates and mock injection for testing.

---

## 4. RDAP Redirect SSRF Hardening & Pre-Connection DNS Resolution

Located in [`backend/app/services/rdap_service.py`](file:///e:/Ware/OSINT%20Dashboard/backend/app/services/rdap_service.py):

To prevent SSRF and DNS rebinding attacks via RDAP endpoints or redirects:

1. **Approved Hostname Allowlist (`ALLOWED_RDAP_HOSTS`):**
   - Hostnames are validated against an explicit whitelist of official RIR endpoints: `rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`, `rdap.iana.org`, `rdap.nic.ad.jp`, `rdap.nic.br`, `rdap.krnic.net`, `rdap.twnic.tw`.

2. **Pre-Connection DNS Resolution:**
   - Before `httpx` connects to any initial RDAP URL or redirect destination:
     1. Hostname is extracted and checked against `ALLOWED_RDAP_HOSTS`.
     2. `A` and `AAAA` records are resolved using `dnspython`.
     3. Every resolved IP is validated with `is_public_ip()`.
     4. If the destination resolves to private (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, or reserved ranges, the request is **immediately blocked**.

3. **Multi-Hop Validation & Redirect Bounds:**
   - Pre-connection DNS and allowlist checks are enforced on **every redirect hop**.
   - Maximum redirect limit is strictly capped at **3 hops** (`follow_redirects=False` with manual hop validation).
   - Response bodies are capped at **128 KB** streaming limit.

---

## 5. API Endpoints

| Method | Path | Summary | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/investigations/{id}/enrich/ip` | **Run IP Intelligence** | Enriches discovered public IPs, records `IPObservation` entities linked with a new `ScanRun`, and saves cryptographic RDAP evidence. |
| `GET` | `/api/investigations/{id}/ip-addresses` | **List IP Addresses** | Returns normalized IP address assets, their current ASN pointer, organization, and country. |
| `GET` | `/api/investigations/{id}/ip-observations` | **List IP Observations** | Returns historical point-in-time IP-to-ASN scan observations across all or specific `ScanRun` IDs (`?scan_run_id=UUID`). |
| `GET` | `/api/investigations/{id}/asns` | **List Discovered ASNs** | Returns distinct Autonomous Systems observed across the investigation's IP assets. |

---

## 6. Testing & Verification

- **Backend Pytest Suite:** 90 tests passing (`pytest tests/ -v`).
  - Unit tests for IP normalization and public/private classification.
  - Team Cymru DNS TXT IPv4 and IPv6 ASN lookups.
  - IANA IPv4 and IPv6 RDAP bootstrap mappings for all 5 RIRs.
  - SSRF pre-connection DNS resolution tests (blocking private, loopback, link-local, and unauthorized redirects).
  - Multi-scan historical isolation tests verifying Scan A (`ASN 100`) vs Scan B (`ASN 200`) persistence and queryability.
  - Alembic migration tests for `ip_observations` table and constraints.
- **Frontend Build:** `npm run build` compiled with 0 errors.

---

## 7. Known Limitations & Explicit Scope Boundaries

- **Bootstrap Registry Coverage:** While canonical /8 and major /12 IPv6 allocations cover the vast majority of allocated space, multi-RIR transfers or smaller sub-delegations rely on authoritative RIR redirects (which are SSRF-validated).
- **Stage 5+ Boundary (Strictly Unimplemented):**
  - No technology fingerprinting or HTTP security header checks (Stage 5).
  - No CVE intelligence, NVD/CISA KEV correlation (Stage 6).
  - No graph engines, risk scoring, change monitoring, or executive report generation (Stage 7+).
