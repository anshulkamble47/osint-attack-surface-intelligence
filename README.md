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

- [x] **Stage 0 — Project Foundation (Completed)**
  - Docker Compose configuration for PostgreSQL 16.
  - FastAPI backend with Pydantic Settings, CORS, and structured logging.
  - Live PostgreSQL database health probe and `/api/health` endpoint.
  - React + TypeScript + Vite frontend communicating with backend.
  - Comprehensive `.gitignore`, `.env.example`, and test suite.
- [x] **Stage 1 — Architecture & Database Schema Design (Completed)**
  - 18 SQLAlchemy 2.0 ORM domain models (`User`, `Target`, `Investigation`, `ScanRun`, `Asset`, `Domain`, `Subdomain`, `DNSRecord`, `ASN`, `IPAddress`, `ServiceExposure`, `Certificate`, `Technology`, `TechnologyVulnerability`, `Vulnerability`, `Finding`, `Evidence`, `AssetRelationship`, `ChangeRecord`, `TimelineEvent`).
  - Strict separation of observed technology vs. potential CVE matches requiring verification.
  - Cryptographic evidence integrity model with SHA-256 hash validation.
  - Directional graph edges for the Attack Surface Correlation Graph.
  - Alembic migration environment and initial schema migration `001_initial_schema.py`.
  - Comprehensive model tests in `tests/test_models.py` (9/9 automated tests passing).
- [ ] **Stage 2** — Backend Core Foundation & Authentication
- [ ] **Stage 3** — Certificate Transparency & DNS Discovery
- [ ] **Stage 4** — IP / ASN / RDAP Infrastructure Intelligence
- [ ] **Stage 5** — Technology Fingerprinting & HTTP Security Analysis
- [ ] **Stage 6** — Vulnerability Intelligence & CVE Correlation
- [ ] **Stage 7** — Asset Correlation Engine & Attack-Surface Graph
- [ ] **Stage 8** — Findings, Risk/Context Engine & Evidence Integrity
- [ ] **Stage 9** — Scan History, Change Detection & Timeline
- [ ] **Stage 10** — React Dashboard & Investigation Management UI
- [ ] **Stage 11** — AI Security Analyst (Groq LLM Integration)
- [ ] **Stage 12** — Automated PDF Report Generation (ReportLab)
- [ ] **Stage 13** — Comprehensive Testing, Hardening & Evaluation
