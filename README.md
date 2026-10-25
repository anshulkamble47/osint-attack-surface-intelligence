# OSINT-Based Attack Surface Intelligence & Risk Analysis Platform

An automated, evidence-backed cybersecurity platform that discovers, correlates, analyzes, monitors, and reports publicly observable attack-surface information associated with authorized organizations and infrastructure.

---

> [!IMPORTANT]
> **Ethical & Legal Notice:** This platform is designed exclusively for authorized cybersecurity assessments, organizational attack-surface management, and educational laboratory research. All scanning and reconnaissance activities must be performed strictly within authorized scope and adhere to legal and ethical boundaries.

---

## 1. Project Purpose & Philosophy

Modern organizations expose diverse internet-facing assets—domains, subdomains, certificates, IP addresses, web technologies, and cloud services. Traditional OSINT tools often act as disconnected dashboards aggregating raw API results.

This platform implements an end-to-end intelligence lifecycle:
```
Discover → Validate → Correlate → Analyze → Monitor → Preserve → Explain → Report
```

- **Discover & Validate:** Discovers hostnames via Certificate Transparency and validates active reachability through DNS.
- **Correlate:** Builds an interconnected attack surface relationship graph (Organization → Domain → Subdomain → IP → ASN → Technology → Potential Vulnerability).
- **Analyze & Explain:** Distinguishes observed facts from probabilistic inferences and potential CVE matches, calculating transparent context scores.
- **Monitor & Preserve:** Tracks changes across historical scan baselines and preserves observation integrity using cryptographic hashes (SHA-256).
- **Report:** Produces automated, explainable intelligence reports for technical teams and leadership.

---

## 2. High-Level System Architecture

```
                                  USER INTERFACE
                   (React 18 + TypeScript + Vite + Tailwind/CSS)
                                        │
                                        ▼
                               FASTAPI REST API
                         (Python 3.13 + SQLAlchemy 2)
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
     INTELLIGENCE SERVICES                                DATABASE (PostgreSQL)
  - CT & DNS Discovery (crt.sh, dnspython)             - Relational Asset Model
  - IP, ASN & RDAP Intelligence                        - Evidence & SHA-256 Hashes
  - Web Technology Fingerprinting                      - Scan Baselines & Diffs
  - Vulnerability Intelligence (NVD/CVE)               - Vulnerability Records
  - Graph Correlation Engine
  - AI Security Analyst (Groq API)
  - Cryptographic Evidence & Reports (ReportLab)
```

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Vite, Modern CSS / Glassmorphism, Lucide Icons |
| **Backend** | Python 3.13, FastAPI, Pydantic v2, Pydantic Settings, SQLAlchemy 2.0 |
| **Database** | PostgreSQL 16 (Alpine via Docker Compose), `psycopg` 3 binary driver |
| **Testing** | Pytest, FastAPI TestClient, HTTPX |
| **Orchestration** | Docker, Docker Compose, Git |

---

## 4. Project Directory Structure

```
OSINT Dashboard/
├── .env.example               # Environment variable template
├── .gitignore                 # Standard Python, Node, Docker, Secret ignores
├── docker-compose.yml         # PostgreSQL 16 Alpine container definition
├── README.md                  # Project documentation and operational guide
│
├── backend/
│   ├── requirements.txt       # Backend Python dependencies
│   └── app/
│       ├── __init__.py        # Backend package definition
│       ├── main.py            # FastAPI entrypoint, middleware, lifespan
│       ├── api/
│       │   ├── __init__.py
│       │   └── health.py      # Health & database probe endpoints
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py      # Pydantic Settings configuration
│       │   └── logging.py     # Structured application logger
│       └── database/
│           ├── __init__.py
│           └── connection.py  # SQLAlchemy engine & health probe
│
├── frontend/
│   ├── package.json           # Frontend dependencies & scripts
│   ├── tsconfig.json          # TypeScript compiler configuration
│   ├── vite.config.ts         # Vite server & backend API proxy
│   ├── index.html             # Application HTML shell
│   └── src/
│       ├── App.tsx            # Foundation dashboard & status monitor
│       ├── main.tsx           # React DOM root entrypoint
│       ├── index.css          # Design system, theme tokens & glassmorphism
│       ├── services/
│       │   └── api.ts         # Backend API client
│       └── types/
│           └── api.ts         # Health check and API interfaces
│
├── docs/                      # Technical documentation & stage guides
│   └── STAGE_0_FOUNDATION.md
│
├── docker/                    # Docker configs and init scripts
└── tests/
    ├── __init__.py
    └── test_health.py         # Automated API & database health tests
```

---

## 5. Prerequisites

Ensure the following tools are installed on your host system:
- **Python 3.13+**
- **Node.js 20+** & **npm 10+**
- **Docker Desktop** (or Docker Engine with Compose plugin)
- **Git**

---

## 6. Quickstart Setup Guide

### Step 1: Clone and Configure Environment

```bash
# Copy the environment template
copy .env.example .env
```

### Step 2: Start PostgreSQL Database Container

```bash
# Launch PostgreSQL 16 in the background
docker compose up -d

# Verify container status
docker compose ps
```

### Step 3: Set Up and Run Backend

```bash
# Navigate to project root and create virtual environment
python -m venv backend/.venv

# Activate virtual environment (Windows PowerShell)
backend\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r backend/requirements.txt

# Start FastAPI development server
backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

FastAPI will be available at:
- **Root Info:** `http://localhost:8000/`
- **Health Check:** `http://localhost:8000/api/health`
- **Interactive Swagger Docs:** `http://localhost:8000/api/docs`

### Step 4: Set Up and Run Frontend

```bash
# Open a new terminal and navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

The frontend dashboard will be accessible at:
- `http://localhost:5173`

---

## 7. Running Automated Tests

```bash
# Run backend health & integration tests
backend\.venv\Scripts\python.exe -m pytest tests/ -v
```

---

## 8. Current Implementation Status

### Completed Core Platform Modules (Stages 0 – 10)

- [x] **Stage 0 — Project Foundation**
  - Containerized PostgreSQL 16 environment via Docker Compose with health checks.
  - FastAPI asynchronous backend with Pydantic Settings, CORS middleware, and structured logging.
  - Live PostgreSQL database health probe and `/api/health` monitoring endpoint.
  - React 18 + TypeScript + Vite frontend client connected to the backend.
  - Comprehensive `.gitignore`, `.env.example`, and baseline health tests.

- [x] **Stage 1 — Architecture & Database Schema Design**
  - 18 SQLAlchemy 2.0 ORM models (`User`, `Target`, `Investigation`, `ScanRun`, `Asset`, `Domain`, `Subdomain`, `DNSRecord`, `ASN`, `IPAddress`, `ServiceExposure`, `Certificate`, `Technology`, `TechnologyVulnerability`, `Vulnerability`, `Finding`, `Evidence`, `AssetRelationship`, `ChangeRecord`, `TimelineEvent`).
  - Strict separation of observed technology facts from potential CVE matches requiring verification.
  - Cryptographic evidence integrity model with SHA-256 hash tracking.
  - Directional graph edges for the Attack Surface Correlation Graph.
  - Alembic database migration environment with zero schema drift.

- [x] **Stage 2 — Backend Core Foundation & Authentication**
  - Secure salted password hashing using Bcrypt (cost factor 12) / Argon2.
  - JWT token management (HMAC-SHA256) with configurable expiration.
  - Authentication endpoints: `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`.
  - Reusable role-based access control (RBAC) dependencies (`admin`, `analyst`, `auditor`).

- [x] **Stage 3 — Certificate Transparency & DNS Discovery**
  - Multi-provider Certificate Transparency discovery engine (`crt.sh` primary with resilient automatic fallback to `Certspotter`).
  - Wildcard / apex deduplication and Subject Alternative Name (SAN) extraction.
  - Active DNS record probing (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`) with thread-safe query caching.
  - Strict pre-flight SSRF protection blocking private RFC 1918, loopback, link-local, and reserved IP ranges.
  - Reachability engine probing ports 80/HTTP and 443/HTTPS with response-time tracking and HTML title extraction.

- [x] **Stage 4 — IP / ASN / RDAP Infrastructure Intelligence**
  - Autonomous System Number (ASN) intelligence and BGP routing prefix mapping.
  - RDAP registry queries with in-memory caching and timeout resilience.
  - IP geolocation, organization attribution, and reverse DNS lookup.
  - `IPObservation` point-in-time tracking across scan runs to detect infrastructure migration.

- [x] **Stage 5 — Web Technology Fingerprinting & HTTP Security Analysis**
  - Passive technology fingerprinting using headers, cookies, and DOM markers (Wappalyzer signatures).
  - Explicit observed version extraction without speculative guessing.
  - HTTP security header evaluation (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
  - Passive TLS session inspection with direct IP pinning (`socket.create_connection`) preserving TLS Server Name Indication (SNI) to prevent DNS rebinding attacks.

- [x] **Stage 6 — Vulnerability Intelligence & CVE Correlation**
  - Integration with NIST National Vulnerability Database (NVD) via CPE 2.3 match criteria.
  - Cross-referencing against CISA Known Exploited Vulnerabilities (KEV) catalog.
  - Strict separation of observed facts from probabilistic CVE matches: findings default to `requires_verification`.
  - Evidence hashes (SHA-256) generated for every correlated CVE record.

- [x] **Stage 7 — Asset Correlation Engine & Attack-Surface Graph**
  - Deterministic graph topology: Organization → Domain → Subdomain → IP → ASN → Service → Technology → Vulnerability / Certificate.
  - Strictly prevents false shared-ownership inferences (e.g. shared cloud CDNs/ASNs).
  - Graph traversal endpoints returning nodes, edges, cycle resistance, and statistics.
  - ScanRun point-in-time historical graph isolation.

- [x] **Stage 8 — Findings, Contextual Risk Scoring & Evidence Integrity**
  - Explainable factor-based contextual risk scoring formula (0–100):
    $$\text{Risk Score} = \text{Base CVSS} + \text{KEV Bonus (+15)} + \text{Internet Exposure (+10)} + \text{Confidence Adjustment (+5/-10)}$$
  - Categorization into CRITICAL, HIGH, MEDIUM, LOW, and INFO.
  - Deduplication and idempotency across repeated scans.
  - Cryptographic evidence validation linking findings to raw observations.

- [x] **Stage 9 — Attack Surface Monitoring & Assessment Snapshots**
  - Complete Assessment Snapshot architecture ensuring only coherent point-in-time states are diffed.
  - Disqualification of isolated modular runs (e.g., preventing false service removals like run #21 → #22).
  - First-snapshot baseline semantics (*"Baseline Established — No Prior Snapshot for Diffing"*).
  - Deterministic change detection: `ADDED`, `REMOVED`, and `MODIFIED` across subdomains, DNS records, IPs, services, technologies, vulnerabilities, and certificates.

- [x] **Stage 10 — React Dashboard & Investigation Management UI**
  - Premium glassmorphic cybersecurity dashboard built with React 18, TypeScript, and Vite.
  - 9 integrated operational views:
    1. **Overview Dashboard:** Attack surface metrics, risk posture, discovery distribution, and one-click quick actions.
    2. **Subdomain Inventory:** Searchable hostname table, resolving state filters, tags, and CT provenance.
    3. **DNS Infrastructure:** A, AAAA, CNAME, MX, NS, TXT record mapping with resolver telemetry.
    4. **IP & ASN Intelligence:** Autonomous System details, routing prefixes, and reverse DNS mapping.
    5. **Services & Technologies:** HTTP status, titles, security headers (HSTS, CSP, XFO, etc.), and TLS cipher/cert metadata.
    6. **Vulnerabilities & CVEs:** Correlated CVEs, CVSS severity breakdown, and CISA KEV badges.
    7. **Findings & Risk Scoring:** Factor breakdown (Base + KEV + Exposure + Confidence), evidence hashes, and remediation notes.
    8. **Monitoring & Changes:** Assessment snapshot selector, snapshot capture, baseline indicator, and diffing table.
    9. **Attack Surface Graph:** Interactive 2D canvas with node filtering, edge badges, and detail inspection drawers.
  - Step-by-step pipeline execution triggers with execution duration and JSON telemetry inspector.
  - Production frontend build verified with 0 TypeScript/bundling errors.

- [x] **Automated Testing Suite**
  - 265 / 265 unit and integration tests passing (`pytest tests/ -v`):
    - `tests/test_auth.py`: 13 passed
    - `tests/test_correlation_graph.py`: 24 passed
    - `tests/test_ct_discovery.py`: 25 passed
    - `tests/test_dns_reachability.py`: 34 passed
    - `tests/test_findings_risk.py`: 22 passed
    - `tests/test_health.py`: 3 passed
    - `tests/test_ip_asn_rdap.py`: 35 passed
    - `tests/test_models.py`: 7 passed
    - `tests/test_monitoring_changes.py`: 33 passed
    - `tests/test_technology_security.py`: 49 passed
    - `tests/test_vulnerability_intelligence.py`: 20 passed

---

### Future Implementation Roadmap (Stages 11 – 13)

- [ ] **Stage 11 — AI Security Analyst (Groq LLM Integration)**
  - Automated natural language executive threat summaries and context narratives.
  - Remediation recommendations prioritizing actionable, high-exposure findings.
  - Analysis of correlated vulnerabilities against organizational asset exposure.
- [ ] **Stage 12 — Automated PDF Report Generation (ReportLab)**
  - Executive summary and technical intelligence PDF export.
  - Visual attack surface breakdown, risk matrices, and cryptographic evidence audit logs.
- [ ] **Stage 13 — Production Deployment, CI/CD & Benchmarking**
  - Multi-stage production Docker Compose orchestration.
  - Continuous integration workflows for automated testing and linting.
  - Performance benchmarking for large-scale multi-thousand asset targets.
