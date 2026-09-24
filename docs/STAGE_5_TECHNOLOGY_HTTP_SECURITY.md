# Stage 5: Technology Fingerprinting & HTTP Security Intelligence

## 1. Overview & Objective

Stage 5 enriches the attack surface discoveries from Stages 3A, 3B, and 4 with passive, structured HTTP metadata, technology fingerprinting with concrete evidence retention, deterministic HTTP security-header observations, and safe TLS connection metadata.

The enrichment flow operates strictly upon resolving subdomains and services identified in previous stages, enforcing strict SSRF protections and maintaining complete scan history isolation.

```
Stage 3B Resolving Subdomains
              │
              ▼
   Stage 5 HTTP Probe (Port 80 HTTP / Port 443 HTTPS)
              │
    ┌─────────┴───────────────┬────────────────────────┬──────────────────────┐
    ▼                         ▼                        ▼                      ▼
HTTP Metadata           Technology Fingerprint     Security Headers        TLS Metadata
(Status, Title,         (Signatures, Evidence,     (HSTS, CSP, XFO,        (Version, Cipher,
Server, Headers)         Version, CPE)             XCTO, Referrer, etc.)    Issuer, SANs)
    │                         │                        │                      │
    └─────────────────────────┼────────────────────────┴──────────────────────┘
                              ▼
        Persistence: ServiceExposure & Technology Records
            (historical isolation via scan_run_id)
```

---

## 2. SSRF Protection & Safe HTTP Probing

Stage 5 reuses and extends the strict SSRF-safe networking model established in Stages 3B and 4:

1. **Pre-flight & Per-Hop DNS Validation**:
   - Every target hostname is resolved prior to connection.
   - Any hostname resolving to a non-public IP (private `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback `127.0.0.0/8`, `::1`, link-local `169.254.0.0/16`, `fe80::/10`, multicast, or reserved ranges) is blocked upfront with an explanatory `SSRF Blocked` observation.
2. **Redirect Validation & Bound Limits**:
   - Redirects are manually handled (`follow_redirects=False`) with each hop re-evaluating hostname and resolved IP safety against the IP filter.
   - A maximum of 3 redirect hops is enforced to avoid infinite loops or open-redirect abuse.
3. **Bounded Response Processing**:
   - Response bodies are streamed and bounded at 64 KB (`65,536 bytes`) to prevent decompression bombs and memory exhaustion.
4. **Strict HTTP Timeouts**:
   - Connect and read timeouts are set to 3.0 seconds (`timeout=3.0`).
5. **No Arbitrary URL Fetching**:
   - The platform does not expose any endpoint for arbitrary URL fetching. Probing only executes against authenticated investigation domain assets.

---

## 3. Technology Fingerprinting Engine

The fingerprinting engine (`TechnologyFingerprintProvider`) uses a structured signature system with strict evidence retention:

### Signature Categories & Rules
- **Web Servers**:
  - `nginx`: Server header `nginx(?:/([0-9.]+))?` -> `cpe:2.3:a:f5:nginx:<version>:*:*:*:*:*:*:*`
  - `Apache`: Server header `Apache(?:/([0-9.]+))?` -> `cpe:2.3:a:apache:http_server:<version>:*:*:*:*:*:*:*`
  - `Microsoft-IIS`: Server header `Microsoft-IIS(?:/([0-9.]+))?` -> `cpe:2.3:a:microsoft:internet_information_services:<version>:*:*:*:*:*:*:*`
  - `Caddy`: Server header `Caddy(?:/v?([0-9.]+))?` -> `cpe:2.3:a:caddyserver:caddy:<version>:*:*:*:*:*:*:*`
  - `LiteSpeed`: Server header `LiteSpeed` -> `cpe:2.3:a:litespeedtech:litespeed_web_server:*:*:*:*:*:*:*`
  - `OpenResty`: Server header `openresty(?:/([0-9.]+))?` -> `cpe:2.3:a:openresty:openresty:<version>:*:*:*:*:*:*:*`
- **CDNs / Reverse Proxies**:
  - `Cloudflare`: `server: cloudflare`, `cf-ray` header.
  - `Varnish`: `x-varnish` or `via: varnish` header.
  - `CloudFront`: `via: ...cloudfront.net` or `x-amz-cf-id` header.
- **Content Management Systems (CMS)**:
  - `WordPress`: `meta[name=generator]` with WordPress version, `/wp-content/`, `/wp-includes/`.
  - `Drupal`: `x-generator: Drupal`, `Drupal.settings`, `meta[name=Generator]` Drupal.
  - `Joomla`: `meta[name=generator]` Joomla, `/media/system/js/`.
  - `Shopify`: `cdn.shopify.com`, `x-shopify-stage`, `Shopify.shop`.
- **Frameworks & Runtimes**:
  - `PHP`: `x-powered-by: PHP/x.y.z`, `PHPSESSID` cookie.
  - `ASP.NET`: `x-powered-by: ASP.NET`, `x-aspnet-version`, `ASP.NET_SessionId` cookie.
  - `Express`: `x-powered-by: Express`.
  - `Django`: `csrftoken` cookie with standard Django cookie signatures.
  - `Laravel`: `laravel_session` cookie, `x-powered-by: Laravel`.
  - `Next.js`: `__NEXT_DATA__` JSON script tag, `x-powered-by: Next.js`.
  - `Nuxt.js`: `__NUXT__` window variable / element, `x-powered-by: Nuxt`.
- **JavaScript & UI Libraries**:
  - `React`: `data-reactroot`, `react.production.min.js`, `_reactListening`.
  - `Vue.js`: `data-v-` scoped attributes, `vue.runtime.min.js`.
  - `Angular`: `ng-version="x.y.z"`, `ng-app`, `ng-controller`.
  - `jQuery`: `jquery(?:-([0-9.]+))?\.min\.js`, `window.jQuery`.
  - `Bootstrap`: `bootstrap(?:-([0-9.]+))?\.min\.(?:css|js)`.

### Strict Evidence & Version Extraction
- **No Guessing**: If a version token is not explicitly observed in the evidence (headers, scripts, meta tags), `version` is recorded as `None` and CPE version is left wildcarded.
- **Evidence Fields**: Every detection preserves `evidence` (e.g. matched header or HTML substring) and `evidence_source` (e.g. `headers`, `meta_generator`, `cookies`, `body`).

---

## 4. HTTP Security Headers Analysis

The security-headers engine deterministically inspects standard security headers with factual, objective descriptions:

| Header | Evaluated Directives / Conditions | Factual Classification |
|---|---|---|
| **Strict-Transport-Security (HSTS)** | `max-age`, `includeSubDomains`, `preload` | `configured` (HTTPS), `missing` (HTTPS), `n/a` (HTTP) |
| **Content-Security-Policy (CSP)** | `default-src`, `script-src`, `report-uri` | `configured`, `missing` |
| **X-Frame-Options** | `DENY`, `SAMEORIGIN` | `configured`, `custom`, `missing` |
| **X-Content-Type-Options** | `nosniff` | `configured`, `custom`, `missing` |
| **Referrer-Policy** | `strict-origin-when-cross-origin`, `no-referrer`, etc. | `configured`, `missing` |
| **Permissions-Policy** | Directives restricting browser features | `configured`, `missing` |
| **Cross-Origin-Opener-Policy (COOP)** | `same-origin`, `same-origin-allow-popups` | `configured`, `missing` |
| **Cross-Origin-Resource-Policy (CORP)**| `same-origin`, `same-site`, `cross-origin` | `configured`, `missing` |

*Note: In accordance with Stage 5 scope boundaries, missing security headers are recorded as factual configuration states and are NOT flagged as vulnerabilities or assigned risk scores.*

---

## 5. TLS Metadata Inspection

For HTTPS endpoints (port 443 only), passive socket metadata inspection extracts:
- Negotiated TLS protocol version (e.g. `TLSv1.3`, `TLSv1.2`)
- Negotiated Cipher Suite (e.g. `TLS_AES_256_GCM_SHA384`)
- Certificate Subject Common Name (`CN`)
- Certificate Issuer (`O`, `CN`)
- Certificate Validity Dates (`notBefore`, `notAfter`)
- Subject Alternative Names (SAN list)

HTTP services (port 80) skip TLS extraction. Any TLS connection failures or timeouts are handled gracefully without aborting the investigation.

---

## 6. Historical ScanRun Isolation

Stage 5 stores observations per `ScanRun`:
- Each execution of `/api/investigations/{id}/fingerprint` creates a new `ScanRun` (e.g. Run #1, Run #2).
- `ServiceExposure` and `Technology` database records are tagged with `scan_run_id`.
- Scans executed across different points in time maintain their historical state independently (e.g., Scan A reflecting Nginx 1.20 and missing HSTS, Scan B reflecting Apache 2.4 and configured HSTS).

---

## 7. API Endpoints & RBAC

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/investigations/{id}/fingerprint` | Analyst (Owner/Admin) | Triggers HTTP probing, technology detection, security-header analysis, and TLS inspection. |
| `GET` | `/api/investigations/{id}/technologies` | Analyst (Owner/Admin/Viewer) | Retrieves all detected technologies with versions, categories, CPEs, and evidence. |
| `GET` | `/api/investigations/{id}/security-headers`| Analyst (Owner/Admin/Viewer) | Retrieves factual security header analysis for each exposed service. |
| `GET` | `/api/investigations/{id}/tls-metadata` | Analyst (Owner/Admin/Viewer) | Retrieves observed TLS parameters for HTTPS services. |

---

## 8. Explicit Stage 6+ Scope Boundaries

Stage 5 strictly excludes:
- CVE lookups, NVD mapping, or vulnerability correlation (Stage 6).
- Vulnerability scanning, active exploitation, or fuzzing.
- Attack surface graph generation or path correlation (Stage 7).
- Risk scoring or priority calculations (Stage 8).
- Continuous monitoring or change alerting (Stage 9).
- AI summaries or automated reporting/PDF generation (Stages 11 & 12).
