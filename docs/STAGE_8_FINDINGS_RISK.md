# Stage 8: Findings, Contextual Risk Scoring & Evidence Intelligence

## 1. Architectural Overview & Objective

Stage 8 introduces the **Security Findings, Contextual Risk Scoring, and Evidence Intelligence Layer** to the OSINT Platform. It converts passively collected intelligence from Stages 3 through 7 into explicit, actionable, evidence-backed security findings.

### Pipeline:
$$\text{Observed Asset} \longrightarrow \text{Technology / Exposure / Condition} \longrightarrow \text{Vulnerability Intelligence} \longrightarrow \mathbf{Finding} \longrightarrow \mathbf{Contextual\ Risk\ Scoring} \longrightarrow \mathbf{Cryptographic\ Evidence}$$

### Core Principle:
- **No Rediscovery:** Stage 8 does not perform new network queries or discover new assets/CVEs. It deterministically processes observations already recorded in the database.
- **Evidence-Backed Findings:** Every security finding must have a deterministic reason for existing (e.g. an observed missing security header, an expired TLS certificate, or a correlated CVE matching an observed technology).
- **No Findings From Technology Alone:** An observed benign technology (e.g. `React 18.2.0`) does not produce a finding simply because it exists.

---

## 2. Finding Classification & Generation Rules

| Finding Type | Category | Detection Condition / Provenance Source | Base Severity | Example Finding Title |
| :--- | :--- | :--- | :--- | :--- |
| `VULNERABILITY` | `vulnerability` | `TechnologyVulnerability` correlation link (Stage 6) between observed `Technology` and `Vulnerability` (NVD/CISA). | Inherited from `Vulnerability.severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) | *Potential Vulnerability: CVE-2021-44228 affecting Apache Log4j 2.14.1* |
| `SECURITY_HEADER` | `security_header` | Missing critical security response headers on public HTTP/HTTPS service (Stage 5): `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`. | `MEDIUM` (HSTS) / `LOW` (CSP, XFO, XCTO) | *Missing HTTP Strict Transport Security (HSTS) on port 443* |
| `TLS_SECURITY` | `tls_security` | Expired Certificate (`cert.is_expired == True`) or Deprecated Protocol Version (`TLSv1.0`, `TLSv1.1`, `SSLv3`, `SSLv2`) in `ServiceExposure` (Stages 3A & 5). | `HIGH` (Expired cert) / `MEDIUM` (Deprecated TLS) | *Expired TLS Certificate for api.example.com* |
| `SERVICE_EXPOSURE` | `service_exposure` | Cleartext HTTP service listening on port 80 without automatic redirection to HTTPS (Stages 3B & 5). | `LOW` | *Cleartext HTTP Service Exposed on Port 80* |
| `CONFIGURATION` | `configuration` | Explicit measurable configuration weakness (e.g. debug headers or verbose banner). | `LOW` / `INFO` | *Verbose Server Information Disclosure* |

---

## 3. Transparent, Factor-Based Contextual Risk Model

The platform contextual risk scoring engine calculates an integer score strictly bounded between **0 and 100**. The formula is deterministic, explainable, and decoupled from raw CVSS scores.

### Formula Definition:

$$\text{Raw Contextual Score} = \text{Base Score} + \Delta_{\text{KEV}} + \Delta_{\text{exposure}} + \Delta_{\text{confidence}}$$

$$\mathbf{Platform\ Risk\ Score} = \min(100, \max(0, \text{round}(\text{Raw Contextual Score})))$$

### Factor Breakdown:

1. **Base Score ($\text{Base Score}$):**
   - **When CVSS v3 is available:** Derived directly from the NVD CVSS base score:
     $$\text{Base Score} = \text{round}(\text{CVSS v3.1 Base Score} \times 10) \quad \in [0, 100]$$
   - **When CVSS is unavailable (Severity Baseline Mapping):**
     - `CRITICAL` $\implies 75$
     - `HIGH` $\implies 60$
     - `MEDIUM` $\implies 40$
     - `LOW` $\implies 20$
     - `INFO` $\implies 5$

2. **CISA KEV Adjustment ($\Delta_{\text{KEV}}$): $+15$ points**
   - Applied when the CVE is cataloged in CISA's Known Exploited Vulnerabilities catalog.
   - *Explanation:* Indicates elevated probability of in-the-wild automated exploit activity.

3. **External Internet Exposure Adjustment ($\Delta_{\text{exposure}}$): $+10$ points**
   - Applied when the affected component is exposed on a public, externally reachable network service (e.g. port 80/443 with HTTP 200/300/400 status).

4. **Fingerprint Match Confidence Adjustment ($\Delta_{\text{confidence}}$):**
   - **High Confidence ($\ge 0.90$):** $+5$ points (exact version / exact CPE banner match).
   - **Moderate Confidence ($0.61 - 0.89$):** $0$ points.
   - **Lower / Range Confidence ($\le 0.60$):** $-10$ points (generic or broad version constraint).

---

## 4. Platform Risk Categories & Thresholds

| Platform Risk Score | Contextual Level | Operational Definition |
| :--- | :--- | :--- |
| **80 – 100** | **CRITICAL** | Severe exposure or critical vulnerability listed in CISA KEV on internet-facing assets requiring immediate remediation. |
| **60 – 79** | **HIGH** | Significant vulnerability or severe TLS/certificate condition on reachable service. |
| **40 – 59** | **MEDIUM** | Moderate security condition (e.g. missing HSTS, legacy TLS 1.0/1.1 protocol, or medium CVE). |
| **20 – 39** | **LOW** | Minor hardening weakness (e.g. missing CSP/XFO/XCTO headers or cleartext HTTP port 80). |
| **0 – 19** | **INFORMATIONAL** | Informational observation with negligible immediate attack surface impact. |

---

## 5. Critical Terminology & Exploitability Boundaries

To ensure strict factual accuracy in automated assessments, the platform enforces strict semantic boundaries:

1. **CVSS $\neq$ Platform Risk:**
   - **CVSS:** Vulnerability severity metric published by NVD based on hypothetical exploit characteristics.
   - **Platform Risk:** Contextualized asset score incorporating live internet exposure, CISA KEV listing, and fingerprint confidence.
2. **Exposed $\neq$ Vulnerable:**
   - An exposed HTTPS service on port 443 is an intended network state, not a security vulnerability.
3. **Potential Vulnerability $\neq$ Confirmed Exploit:**
   - Passive technology correlation indicates that an observed version matches a vulnerable range; it does not verify whether specific vulnerable code paths are active or unpatched.
4. **CISA KEV Listing $\neq$ Asset Compromise:**
   - KEV membership indicates that a CVE is actively exploited in the wild globally; it does **not** imply that this target asset is compromised.

---

## 6. Historical ScanRun Isolation & Idempotency

- **ScanRun Isolation:** Findings are linked directly to `scan_run_id`. Running a new scan (ScanRun 2) where a vulnerability is patched does **not** mutate or erase historical findings from ScanRun 1.
- **Idempotent Generation:** Unique constraint `uq_investigation_scan_run_finding` on `(investigation_id, scan_run_id, asset_id, category, title)` prevents duplicate finding records. Repeated generation updates existing findings in place.

---

## 7. Cryptographic Evidence & Provenance

Findings link to cryptographic `Evidence` records stored in the `evidence` table with SHA-256 integrity hashes (`sha256_hash`). Each evidence item records the raw observation source (e.g. `http_headers`, `dns_query`, `crt.sh`, `NVD API`) and collection timestamp.

---

## 8. API Specification

### 1. `POST /api/investigations/{investigation_id}/findings/generate`
- **Description:** Deterministically correlates Stage 3–7 intelligence into findings and calculates contextual risk scores for the investigation or specific `scan_run_id`.
- **Response:** `GenerateFindingsResponse` with counts, severity breakdown, risk category breakdown, and list of findings.

### 2. `GET /api/investigations/{investigation_id}/findings`
- **Parameters:** `?scan_run_id=&severity=&status=&finding_type=&category=`
- **Description:** Lists and filters findings for the authenticated analyst.

### 3. `GET /api/investigations/{investigation_id}/findings/{finding_id}`
- **Description:** Returns detailed finding record, transparent factor-by-factor risk explanation, affected asset, technology, vulnerability, and cryptographic evidence.
- **Security:** Strictly enforces investigation ownership to prevent IDOR.

### 4. `PATCH /api/investigations/{investigation_id}/findings/{finding_id}`
- **Body:** `{"status": "open" | "acknowledged" | "resolved" | "suppressed"}`
- **Description:** Updates the lifecycle state of a finding.
