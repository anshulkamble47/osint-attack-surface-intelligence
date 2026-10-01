# Stage 9: Attack Surface Monitoring & Change Detection

## 1. Architectural Overview & Objective

Stage 9 introduces the **Attack Surface Monitoring & Change Detection Engine** to the OSINT Platform. The purpose of this stage is to compare point-in-time `ScanRun` observations and produce deterministic, evidence-backed `ChangeRecord` entries showing how an organization's externally observable attack surface has evolved over time.

### Core Question Answered:
$$\mathbf{"What\ was\ added,\ removed,\ or\ modified\ between\ scans?"}$$

```
+------------------+         +------------------+
|  ScanRun A       |         |  ScanRun B       |
|  (Baseline Scan) |         |  (Current Scan)  |
+--------+---------+         +--------+---------+
         \                            /
          \                          /
           v                        v
     +------------------------------------+
     |    ChangeDetectionService          |
     |  - Stable Identity Matching        |
     |  - Attribute Diff Computation      |
     |  - Evidence Linkage Preservation   |
     +-----------------+------------------+
                       |
                       v
     +------------------------------------+
     |         ChangeRecord Matrix        |
     |   [+] ADDED                        |
     |   [-] REMOVED                      |
     |   [~] MODIFIED                     |
     +------------------------------------+
```

---

## 2. Core Design Principles & Semantics

### 1. Point-in-Time ScanRun Observations
A `ScanRun` represents an immutable point-in-time snapshot of the target's attack surface. The database state of old scans is never overwritten or mutated to represent new observations.

### 2. Isolated Historical State
Historical observations remain strictly isolated by `scan_run_id`. Comparing Scan 1 with Scan 2 never deletes or modifies records from Scan 1 or Scan 2.

### 3. Explicit Change Types (`ADDED`, `REMOVED`, `MODIFIED`):
- **`ADDED` (+):** An observable entity or property was observed in the current completed ScanRun but was not observed in the baseline ScanRun.
- **`REMOVED` (-):** An observable entity or property was previously observed in the baseline ScanRun but is **not observed in the current completed ScanRun**.
  - *Crucial Semantic Note:* Absence from the current scan is **not** sufficient evidence of physical removal or vulnerability remediation. Network reachability, rate limits, or provider discovery differences can cause an observation to disappear. The platform describes this strictly as "no longer observed in current scan" and does **NOT** automatically label removed vulnerabilities/findings as "remediated", "patched", or "fixed".
- **`MODIFIED` (~):** The entity exists in both scans with the identical logical identity key, but a tracked observable security property changed (e.g. HTTP status changed, TLS version upgraded, security header added, software version updated, expiration status changed).

### 4. Critical Boundary: Change $\neq$ Vulnerability / Compromise
A detected change is an **observable intelligence difference**, not an automatic security finding or compromise:
- Adding a new IP address or changing DNS records is standard infrastructure operations.
- Upgrading software version from `nginx 1.18.0` to `nginx 1.22.0` is a `MODIFIED` change record, representing positive patching rather than a security breach.
- Findings and risk scores (Stage 8) remain distinct from change detection records (Stage 9).

### 5. Passive Coverage & Observation Limitations
Change detection operates strictly on passive OSINT intelligence captured in completed `ScanRuns`. The system does not possess active agents or internal telemetry inside the target network. Therefore:
- The system cannot distinguish "not observed" from "confirmed physically removed".
- Disappearance from an OSINT scan does not prove physical removal or remediation.

---

## 3. Stable Logical Identity Rules & Certificate Handling

To prevent false differences caused by database primary keys or internal timestamps, explicit logical comparison keys are defined for each observation type:

| Observation Category | Tracked Entity | Stable Logical Comparison Key | Meaningful Tracked Fields |
| :--- | :--- | :--- | :--- |
| **Subdomains** | Subdomain / Hostname | `subdomain:{normalized_fqdn}` | `is_resolving`, `discovery_source` |
| **DNS Records** | Resource Record | `dns:{fqdn}:{record_type}` | Set of record values (e.g. IP addresses, MX targets, TXT records) |
| **IP Observations** | Observed IP & ASN | `ip:{ip_address}` | `asn_number`, `asn_name`, `country` |
| **Service Exposures** | Network Service / Endpoint | `service:{asset_value}:{protocol}:{port}` | `http_status`, `tls_version`, `page_title`, `service_name`, `security_headers` |
| **Technologies** | Software / Framework | `technology:{asset_value}:{tech_name}` | `version`, `cpe`, `category`, `confidence` |
| **Vulnerabilities** | CVE Correlation | `vuln:{asset_value}:{tech_name}:{cve_id}` | `severity`, `match_confidence`, `verification_status` |
| **Certificates** | TLS Certificate | `cert:{fqdn}:{fingerprint_sha256}` | `subject_cn`, `issuer`, `valid_to`, `is_expired` |
| **Relationships** | Graph Topology Edge | `rel:{source_asset_id}:{rel_type}:{target_asset_id}` | `relationship_type`, `confidence` |
| **Findings** | Security Assessment | `finding:{asset_id}_{category}_{title}` | `status`, `severity`, `context_score`, `title` |

### Certificate Identity & Replacement Semantics
Because the certificate identity is keyed by `cert:{fqdn}:{fingerprint_sha256}`, certificate renewals or replacements (which generate a new cryptographic key/fingerprint) will naturally and correctly appear as:
- **`REMOVED`** old certificate (`cert:{fqdn}:{old_fingerprint}`)
- **`ADDED`** new certificate (`cert:{fqdn}:{new_fingerprint}`)

A certificate change is classified as **`MODIFIED`** only when tracked metadata changes on the exact same certificate identity (for example, when an existing certificate's `is_expired` flag transitions over time).

---

## 4. Modified Detection Rules

A `MODIFIED` record is created **only** when meaningful observable security properties change. 

### Ignored Fields (Do NOT trigger `MODIFIED`):
- Internal database IDs (`id`, `created_by_id`, `target_id`)
- Timestamps (`created_at`, `updated_at`, `collected_at`, `observed_at`)
- `scan_run_id` references
- Internal database row order or pagination offset

### Tracked Fields Examples:
- **HTTP Status:** `200` $\longrightarrow$ `301` or `500`
- **TLS Protocol:** `TLSv1.2` $\longrightarrow$ `TLSv1.3`
- **Security Headers:** `Strict-Transport-Security` enabled or removed
- **Software Version:** `apache 2.4.49` $\longrightarrow$ `apache 2.4.50`
- **ASN Routing:** `AS13335 (Cloudflare)` $\longrightarrow$ `AS16509 (Amazon)`
- **DNS Resolution:** `is_resolving: False` $\longrightarrow$ `is_resolving: True`

---

## 5. Database Schema & Migration

### ChangeRecord Model (`backend/app/models/change.py`)
```python
class ChangeRecord(Base):
    __tablename__ = "change_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    previous_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    current_scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    
    change_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # ADDED, REMOVED, MODIFIED
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="general", index=True)
    field_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    old_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    new_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("investigation_id", "previous_scan_id", "current_scan_id", "change_type", "field_name", "entity_key", name="uq_change_records_comparison"),
    )
```

### Alembic Migration
- **Revision:** `006_add_monitoring_and_change_details.py`
- Added columns `category`, `entity_key`, `description`, `evidence_id`, `evidence_hash` and unique constraint `uq_change_records_comparison`.

---

## 6. Determinism & Idempotency

Running `compare_scan_runs(investigation_id, baseline_scan_id, current_scan_id)` multiple times is completely idempotent:
1. It looks up existing change records for the exact `(investigation_id, baseline_id, current_id)` combination.
2. If a change record already exists for `(change_type, field_name, entity_key)`, it updates the record in place without duplicating database rows.
3. Database unique constraint `uq_change_records_comparison` guarantees zero duplicate records even under concurrent requests.

---

## 7. REST API Endpoints

### 1. Compare Two Scan Runs
- **Endpoint:** `POST /api/investigations/{investigation_id}/monitoring/compare`
- **Authorization:** `analyst` (owner) or `admin`
- **Request Body (Optional):**
  ```json
  {
    "baseline_scan_run_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "current_scan_run_id": "9ca12f45-1234-4562-b3fc-8c963f66bcde"
  }
  ```
  *(If omitted, automatically compares the previous completed scan against the latest completed scan).*
- **Response (200 OK):**
  ```json
  {
    "investigation_id": "...",
    "baseline_scan_run_id": "...",
    "current_scan_run_id": "...",
    "baseline_scan_run_number": 1,
    "current_scan_run_number": 2,
    "total_changes": 8,
    "added_count": 4,
    "removed_count": 2,
    "modified_count": 2,
    "changes_by_category": {
      "subdomain": 2,
      "service_exposure": 2,
      "technology": 2,
      "vulnerability": 2
    },
    "changes_by_type": {
      "ADDED": 4,
      "REMOVED": 2,
      "MODIFIED": 2
    },
    "changes": [ ... ],
    "compared_at": "2026-10-01T12:00:00Z",
    "message": "Successfully compared ScanRun #1 and ScanRun #2: 8 changes detected."
  }
  ```

### 2. List Change Records
- **Endpoint:** `GET /api/investigations/{investigation_id}/changes`
- **Query Parameters:**
  - `baseline_scan_run_id` (UUID, optional)
  - `current_scan_run_id` (UUID, optional)
  - `change_type` (`ADDED`, `REMOVED`, `MODIFIED`, optional)
  - `category` (`subdomain`, `dns_record`, `ip_observation`, `service_exposure`, `technology`, `vulnerability`, `certificate`, `asset_relationship`, `finding`, optional)
  - `asset_id` (UUID, optional)
  - `limit` (int, default: 100, max: 1000)
  - `offset` (int, default: 0)
- **Response (200 OK):** `ChangeListResponse`

### 3. Monitoring Summary
- **Endpoint:** `GET /api/investigations/{investigation_id}/monitoring/summary`
- **Response (200 OK):** Summary metrics and recent 50 change records.

---

## 8. Authorization & IDOR Protection

1. **Investigation Isolation:**
   - Analysts can only compare and list changes for investigations they created.
   - Attempts to access other analysts' investigations return `403 Forbidden`.
2. **Cross-Investigation Scan Rejection:**
   - If a request specifies a `baseline_scan_run_id` or `current_scan_run_id` belonging to a different investigation, the API immediately rejects the request with `400 Bad Request` ("ScanRun does not belong to this investigation").
3. **Auditor / Admin RBAC:**
   - Admin users have full access across all investigations.

---

## 9. Passive Security Boundary

Stage 9 strictly respects the OSINT passive-intelligence boundary:
- **No Active Network Probing:** Change detection operates entirely against historical database snapshots.
- **No Port Scanning:** Does not initiate network connections.
- **No Exploitation or Brute Force:** Only diffs observable metadata.
