# Stage 1: Architecture & Database Schema Design

## 1. Overview & Architectural Philosophy

Stage 1 designs the foundational data model for the **OSINT-Based Attack Surface Intelligence & Risk Analysis Platform**.

The database architecture directly supports the end-to-end intelligence cycle:
$$\text{Discover} \longrightarrow \text{Validate} \longrightarrow \text{Correlate} \longrightarrow \text{Analyze} \longrightarrow \text{Monitor} \longrightarrow \text{Preserve} \longrightarrow \text{Explain} \longrightarrow \text{Report}$$

---

## 2. Core Entities & Schema Architecture

The database is composed of **18 tables** logically partitioned across 7 functional subsystems:

### 2.1. Identity & Scope
- **`users`**: Platform access control (`admin`, `analyst`, `auditor`) with password hashing and JWT readiness.
- **`targets`**: Authorized organizational boundary or root domain entity.
- **`investigations`**: Grouping container for assessment runs, scoped options, findings, and evidence artifacts.
- **`scan_runs`**: Sequential point-in-time executions used to calculate historical differences.

### 2.2. Asset Hierarchy & DNS Infrastructure
- **`assets`**: Unified core registry linking all discovered digital assets (domains, subdomains, IPs, certificates, services) with lifecycle timestamps, active status, confidence metrics, calculated risk scores, and `last_scan_run_id` (linking to the scan run that last verified the asset).
- **`domains`**: Root domain records with registrar info, nameservers, EPP status codes, and raw RDAP records.
- **`subdomains`**: Discovered hostnames explicitly tracking `is_resolving` (distinguishing active infrastructure from historical Certificate Transparency candidates).
- **`dns_records`**: Observed DNS records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `PTR`) with TTLs, resolver provenance, and `scan_run_id` linking to the specific scan run.
- **`asns`**: Autonomous System Numbers, routing networks, and BGP prefixes.
- **`ip_addresses`**: Geolocation, reverse DNS (PTR), network owner, and ASN relationships.
- **`certificates`**: SSL/TLS certificate records with SHA-256 fingerprints, SAN hostnames, validity ranges, and CT log metadata.
- **`subdomain_certificates`**: Many-to-Many association between subdomains and discovered certificates with `scan_run_id`.

### 2.3. Exposure & Technology Fingerprinting
- **`service_exposures`**: Externally reachable ports, protocols (`tcp`/`udp`), services (`http`, `https`), HTTP response status, page titles, TLS versions, security header evaluations (HSTS, CSP, X-Frame-Options, Referrer-Policy), and `scan_run_id`.
- **`technologies`**: Identified software components (web servers, frameworks, CMS, JS libraries) with version strings, confidence ratings, evidence provenance, and `scan_run_id`.

### 2.4. Vulnerability Intelligence & Correlation
- **`vulnerabilities`**: Structured NVD/CVE repository records with CVSS v3.1 base scores, severity, vector strings, and affected CPE patterns.
- **`technology_vulnerabilities`**: Explicit correlation link adhering to the project mandate: *distinguish observed technology facts from potential CVE matches requiring verification* (`verification_status: requires_verification`).

### 2.5. Findings & Explainable Context Scoring
- **`findings`**: Security observations with human-readable recommendations, reference codes (`F-XXXX`), and transparent context scores (0–100) backed by structured scoring breakdowns:
  - Internet-Facing Asset: $+25$
  - High-Confidence Technology Detection: $+20$
  - High-Severity CVE: $+30$
  - Current Observation Recency: $+15$
  - Corroborated by Multiple Sources: $+10$

### 2.6. Cryptographic Evidence & Integrity
- **`evidence`**: Raw observation payloads (`ct_log`, `dns_query`, `http_headers`, `nvd_record`) coupled with immutable SHA-256 cryptographic hashes (`sha256_hash`), reference IDs (`EV-XXXXX`), and integrity verification helpers.

### 2.7. Graph Correlation & Historical Monitoring
- **`asset_relationships`**: Directional graph edges forming the interconnected Attack Surface Graph ($\text{Domain} \to \text{Subdomain} \to \text{IP} \to \text{ASN} \to \text{Technology} \to \text{Finding}$).
- **`change_records`**: Delta analysis between successive scans ($\text{ADDED}, \text{REMOVED}, \text{MODIFIED}$) tracking infrastructure changes over time.
- **`timeline_events`**: Audit log of historical events for the investigation timeline.

---

## 3. Alembic Migration Strategy

Database versioning is managed through Alembic:
1. `alembic.ini` is configured at the project root with the dynamic PostgreSQL driver URL.
2. `backend/alembic/env.py` binds to `DATABASE_URL` from Pydantic Settings and loads `Base.metadata` from `backend.app.database.base`.
3. The initial migration script `backend/alembic/versions/001_initial_schema.py` defines all 18 tables, indexes, unique constraints, and foreign key cascades.

To apply migrations against PostgreSQL:
```powershell
backend\.venv\Scripts\python.exe -m alembic upgrade head
```

---

## 4. How Later Stages Utilize This Schema

| Stage | Subsystem / Table | Purpose & Workflow |
| :--- | :--- | :--- |
| **Stage 2** (Backend Core & Auth) | `users`, `targets`, `investigations` | User login, JWT sessions, and target initialization. |
| **Stage 3** (CT & DNS Discovery) | `subdomains`, `certificates`, `dns_records` | Query crt.sh, extract SANs, validate active DNS resolution (`is_resolving`). |
| **Stage 4** (IP / ASN / RDAP) | `ip_addresses`, `asns`, `domains` | Resolve IPs, fetch ASN prefixes, and RDAP registration metadata. |
| **Stage 5** (Tech & Headers) | `service_exposures`, `technologies` | Probe HTTP ports, inspect security headers, fingerprint software stacks. |
| **Stage 6** (CVE Correlation) | `vulnerabilities`, `technology_vulnerabilities` | Query NVD CVE records, map CPEs, assign `requires_verification`. |
| **Stage 7** (Graph Engine) | `asset_relationships` | Construct multi-node graph edges for interactive visualization. |
| **Stage 8** (Findings & Evidence) | `findings`, `evidence` | Calculate transparent context scores, store raw JSON with SHA-256 hashes. |
| **Stage 9** (Change & Timeline) | `scan_runs`, `change_records`, `timeline_events` | Compare scan $N$ vs $N-1$, detect new/removed assets, record audit events. |
| **Stage 10** (React UI) | All tables via REST APIs | Display asset inventories, status cards, graph views, and timelines. |
| **Stage 11** (AI Analyst) | `findings`, `assets`, `evidence` | Feed structured observations to Groq LLM for executive summaries. |
| **Stage 12** (PDF Reporting) | All tables | Generate formal evidence-backed PDF attack surface intelligence reports. |
