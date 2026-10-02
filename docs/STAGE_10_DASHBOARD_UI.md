# Stage 10: React Dashboard & Investigation UI

## 1. Overview & Objectives

Stage 10 transforms the frontend into a structured, modular cybersecurity analyst dashboard. It synthesizes all intelligence gathered across Stages 0 through 9 (Certificate Transparency, DNS intelligence, reachability, IP/ASN enrichment, RDAP, HTTP/TLS fingerprinting, NVD/CISA KEV correlation, relationship graph, contextual risk scoring, and monitoring/change detection) into a unified analyst workspace.

### Core Architectural Principle
The frontend serves exclusively as a **visualization, exploration, and analyst workflow interface**. The backend remains the sole authoritative source for authentication, RBAC, asset discovery, deterministic correlation, risk calculation, and change detection. **Zero fake or placeholder metrics** are used; if data is unobserved, explicit empty states with direct pipeline action triggers are displayed.

---

## 2. Target Information Architecture

The analyst experience is structured into 9 dedicated sections accessible via a persistent sidebar:

```
Investigation Workspace
  ├── 1. OVERVIEW             (Executive summary metrics, target scope, active alerts, quick actions)
  ├── 2. ASSETS               (Discovered domains, subdomains, discovery source, status)
  ├── 3. DNS / INFRASTRUCTURE (DNS records, public IP resolutions, ASNs, RDAP allocations)
  ├── 4. SERVICES & TECH      (Exposed TCP ports, tech fingerprinting, security headers, TLS metadata)
  ├── 5. VULNERABILITIES      (Correlated CVEs, CVSS Base vs Contextual Risk, CISA KEV alerts)
  ├── 6. ATTACK SURFACE GRAPH (Deterministic node-link topology, type/rel filters, entity inspector)
  ├── 7. FINDINGS & RISK      (Evidence-backed findings, 0-100 contextual risk score breakdown, lifecycle)
  ├── 8. MONITORING & CHANGES (Point-in-time scan comparison, ADDED/REMOVED/MODIFIED state diffs)
  └── 9. SCANS & DETAILS      (Point-in-time ScanRun execution logs, durations, pipeline triggers)
```

---

## 3. Section Capabilities & Specifications

### 1. Overview Dashboard (`OverviewDashboard.tsx`)
- **Scope Banner:** Identifies active target domain, reference code, client organization, lifecycle status, and creation date.
- **On-Demand Pipeline Bar:** Modular action triggers to execute discovery, DNS probing, IP enrichment, technology fingerprinting, CVE correlation, and findings generation.
- **High-Level Metric Cards:** Real-time counts of discovered assets, resolving subdomains, DNS records, public IPs, exposed services, technologies, correlated CVEs, KEV listings, critical/high findings, and detected surface changes.
- **Top Risk Findings & Recent Changes:** Previews the top 5 critical/high severity findings and recent surface change records with navigation links.

### 2. Discovered Assets (`AssetInventory.tsx`)
- **Asset Catalog:** Categorized table of domains, subdomains, and external assets.
- **Filter Toolbar:** Real-time full-text search (FQDN, type, tags, source) and asset type dropdown selector.
- **Asset Inspector Modal:** Displays UUID, discovery source, confidence rating (0-100%), base risk score, first/last seen timestamps, and assigned tags.
- **Empty State:** Guides analysts to trigger Certificate Transparency (CT) discovery if no assets are recorded.

### 3. DNS & Infrastructure (`DnsInfrastructureView.tsx`)
- **Subtabs:**
  - **DNS Records:** A, AAAA, CNAME, MX, TXT records with record values, TTLs, resolver attribution, and collected timestamps.
  - **IP Addresses:** Resolved public IPv4/IPv6 addresses, ASN association, country, reverse DNS (PTR), and active resolution state.
  - **ASNs & RDAP:** Autonomous System numbers, network operator names, allocated BGP prefixes, and country codes.
- **Ownership Semantics:** Preciseness in labeling network ownership as *"Observed Organization / Network"* rather than asserting domain ownership.

### 4. Services & Technology (`ServicesTechView.tsx`)
- **Subtabs:**
  - **Technologies:** Software names, categories, observed versions (explicitly showing *"Version not observed"* rather than guessing), CPE identifiers, confidence ratings, and detection evidence.
  - **Exposed Services:** Ports, protocols, HTTP status codes, page titles, and reachability state.
  - **Security Headers:** Service URLs, ports, and header evaluations (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) with *Present* / *Missing* status and interpretation.
  - **TLS Metadata:** Cipher suites, TLS protocol versions, Subject CN, Issuer, and validity dates.

### 5. Vulnerability Intelligence (`VulnerabilitiesView.tsx`)
- **Correlated CVE Records:** Detailed table of CVE ID, observed technology, observed version, CVSS base severity, CISA KEV status, correlation status (`POTENTIAL_MATCH`, `REQUIRES_VERIFICATION`, `CONFIRMED_MATCH`), match basis, source, and publish date.
- **CISA KEV Alerting:** Highlighting actively exploited CVEs with ransomware campaign indicators and remediation due dates.
- **Important Distinction:** Explicit banner distinguishing CVSS Base Severity (vulnerability flaw metric) from Platform Contextual Risk (asset exposure, KEV, and confidence weighted metric).
- **Vulnerability Inspector Modal:** Full CVE summary, matched CPEs, CVSS base vector, intelligence source, and remediation recommendations.

### 6. Attack Surface Relationship Graph (`AttackSurfaceGraphView.tsx`)
- **Interactive Views:**
  - **Topology View:** Grouped entity cards by node type (`domain`, `subdomain`, `ip`, `asn`, `service`, `technology`, `vulnerability`, `certificate`).
  - **Node List & Edge List:** Searchable tabular representations of graph vertices and directed relationships.
- **Filters:** By Node Type and Relationship Type (`CONTAINS`, `RESOLVES_TO`, `ANNOUNCED_BY`, `EXPOSES`, `USES_TECHNOLOGY`, `AFFECTED_BY`, `HAS_CERTIFICATE`).
- **Entity Inspector:** Detailed view of selected node identifier, UUID, display label, associated edge links, and raw deterministic metadata JSON.
- **Relationship Legend:** Explains the deterministic semantics of all graph edges.

### 7. Findings & Contextual Risk Workspace (`FindingsRiskView.tsx`)
- **Split Explorer & Inspector Layout:** Browse correlated findings on the left, inspect detailed risk factors and evidence on the right.
- **Side-by-Side Scoring:** Contextual Risk Score (0-100) alongside NVD CVSS Base Score (0-10.0).
- **Transparent Scoring Breakdown:**
  - Base Score Factor
  - CISA KEV Adjustment (+pts and reason)
  - Asset Exposure Adjustment (+pts and reason)
  - Confidence Factor Adjustment (+/- pts and reason)
- **Lifecycle Status Management:** Interactive status selector (`open`, `acknowledged`, `resolved`, `suppressed`) with instant backend synchronization via `PATCH /api/investigations/{id}/findings/{finding_id}/status`.
- **Remediation Guidance:** Clear remediation steps and target asset attribution.

### 8. Monitoring & Change Detection (`MonitoringChangesView.tsx`)
- **ScanRun Diffing:** Compare baseline and current ScanRuns.
- **Summary Metrics:** Total detected changes, Added (+), Removed (-), and Modified (~).
- **Explicit Change Semantics:**
  - `ADDED`: Previously not observed, now observed.
  - `REMOVED`: Previously observed in baseline, not observed in current completed scan (*Absence does not prove remediation or physical deletion*).
  - `MODIFIED`: Observed in both scans with tracked observable property mutations.
- **Diff Inspector:** Side-by-side Baseline State JSON (Old) vs Current State JSON (New) with SHA-256 evidence provenance hash.

### 9. Scan Details & Telemetry (`ScanRunsView.tsx`)
- **Point-in-Time History:** List of all historical scan executions (`run_number`, status, start/end timestamps, execution duration, discovered asset count, resolving count, and findings count).
- **ScanRun Inspector:** Details of scan telemetry, configuration summary, and failure logs if applicable.
- **Investigation Scope:** Complete investigation metadata including UUID, reference code, target domain, organization, and creation timestamp.

---

## 4. Design System & Component Architecture

The frontend follows a modern, dark-mode cybersecurity analyst workspace design system:

### Directory Structure
```
frontend/src/
  ├── components/
  │   ├── common/
  │   │   ├── EmptyState.tsx       (Accessible empty states with action triggers)
  │   │   ├── LoadingSpinner.tsx   (Loading animations)
  │   │   ├── Modal.tsx            (Accessible dialog inspector)
  │   │   ├── RiskScoreBadge.tsx   (0-100 contextual risk score pills)
  │   │   ├── SeverityBadge.tsx    (Critical / High / Medium / Low severity pills)
  │   │   └── StatusBadge.tsx      (Active / Inactive / Open / Resolved status pills)
  │   ├── layout/
  │   │   ├── Header.tsx           (Breadcrumbs, health indicator, analyst profile)
  │   │   └── Sidebar.tsx          (Assessment switcher, 9-tab workspace navigation)
  │   ├── auth/
  │   │   └── AuthView.tsx         (Analyst login & account registration)
  │   ├── overview/
  │   │   └── OverviewDashboard.tsx(Executive summary & quick action triggers)
  │   ├── assets/
  │   │   └── AssetInventory.tsx   (Asset discovery & CT log inspector)
  │   ├── infrastructure/
  │   │   └── DnsInfrastructureView.tsx (DNS, IP routing, ASNs, RDAP)
  │   ├── services/
  │   │   └── ServicesTechView.tsx (Services, technologies, headers, TLS)
  │   ├── vulnerabilities/
  │   │   └── VulnerabilitiesView.tsx (CVE correlation & CISA KEV)
  │   ├── graph/
  │   │   └── AttackSurfaceGraphView.tsx (Deterministic graph topology)
  │   ├── findings/
  │   │   └── FindingsRiskView.tsx (Contextual risk & lifecycle management)
  │   ├── monitoring/
  │   │   └── MonitoringChangesView.tsx (Scan diffing & state comparisons)
  │   └── scans/
  │       └── ScanRunsView.tsx     (Point-in-time scan execution timeline)
  ├── services/
  │   └── api.ts                   (Typed Axios client for backend REST endpoints)
  ├── types/
  │   └── api.ts                   (TypeScript interfaces matching FastAPI schemas)
  ├── index.css                    (Design tokens, CSS variables, glass panels, tables)
  ├── App.tsx                      (Root state coordinator & view router)
  └── main.tsx                     (Application entry point)
```

---

## 5. Security & State Management

1. **Authentication & Authorization:** JWT tokens stored in localStorage, automatically attached to `Authorization: Bearer <token>` headers. Backend RBAC (`ADMIN`, `ANALYST`, `AUDITOR`) and IDOR checks remain authoritative.
2. **Data Authenticity:** All metrics and charts render real data from typed API responses.
3. **Optimistic & Error Handling:** Explicit error banners and loading spinners on all async actions; errors from backend API responses are surfaced clearly without unhandled exceptions.
4. **Scan Isolation:** Findings, assets, and graph nodes are attributed to their respective scan run snapshots.

---

## 6. Verification & Build Results

- **Backend Pytest Suite:** `215 passed in 33.35s` (`tests/`)
- **Frontend Production Build:** `npm run build` passed with zero errors (`dist/assets/index-u5tiaUrK.js 306.34 kB`).
