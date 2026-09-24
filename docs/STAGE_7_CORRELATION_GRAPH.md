# STAGE 7: CORRELATION & ATTACK-SURFACE GRAPH DOCUMENTATION

## 1. Executive Summary & Objective

Stage 7 implements the **Attack-Surface Relationship Graph and Deterministic Correlation Engine** for the OSINT-Based Attack Surface Intelligence & Risk Analysis Platform.

The correlation engine transforms isolated observations discovered across previous stages (Certificate Transparency, DNS Resolution, IP/ASN/RDAP Intelligence, Technology Fingerprinting, HTTP Security, and Vulnerability Intelligence) into an interconnected, evidence-backed relationship graph.

```
Target
  └── Domain: example.com
        └── Subdomain: api.example.com
              ├── IPAddress: 198.51.100.25
              │     └── ASN: AS64500 (GraphCloud Networks)
              ├── ServiceExposure: https (443/tcp)
              ├── Technology: nginx 1.20.0
              │     └── Vulnerability: CVE-2021-23017 (HIGH)
              └── Certificate: CN=api.example.com (Let's Encrypt)
```

---

## 2. Graph Concepts & Architecture

### A. Graph Model
- **Nodes (`GraphNode`)**: First-class digital entities discovered during assessment.
- **Edges (`GraphEdge`)**: Deterministic, evidence-backed connections linking two nodes.
- **Statistics (`GraphStatistics`)**: Summary aggregates computed directly from graph contents (node counts by type, edge counts by relationship).
- **Historical ScanRun Isolation**: Every edge and scan-specific node is attributed to a point-in-time `scan_run_id`.

### B. Stable Identifier Format
All node identifiers use deterministic, human-readable prefix notation with underlying database UUIDs or canonical identifiers:
- `domain:<asset_id>`
- `subdomain:<asset_id>`
- `ip:<asset_id>`
- `asn:<asn_id>`
- `service:<service_id>`
- `technology:<technology_id>`
- `vulnerability:<cve_id>`
- `certificate:<certificate_id>`

Edge identifiers use canonical source-target-relationship tuples:
- `edge:<source_id>-><target_id>:<RELATIONSHIP_TYPE>`

---

## 3. Node & Edge Type Definitions

### Node Types
| Node Type | Source Entity | Key Metadata Attributes |
|:---|:---|:---|
| `domain` | `Domain` / `Asset` | `domain_name`, `registrar`, `nameservers`, `status` |
| `subdomain` | `Subdomain` / `Asset` | `subdomain_name`, `is_resolving`, `discovery_source` |
| `ip` | `IPAddress` / `Asset` | `ip_address`, `ip_version`, `reverse_dns`, `country`, `organization` |
| `asn` | `ASN` | `asn_number`, `name`, `country`, `allocated_prefix` |
| `service` | `ServiceExposure` | `port`, `protocol`, `service_name`, `http_status`, `tls_version`, `page_title` |
| `technology` | `Technology` | `name`, `version`, `cpe`, `category`, `confidence`, `evidence_source` |
| `vulnerability` | `Vulnerability` | `cve_id`, `title`, `severity`, `cvss_v3_score`, `verification_status` |
| `certificate` | `Certificate` | `fingerprint_sha256`, `subject_cn`, `issuer`, `valid_to`, `is_expired` |

### Explicit Edge Types & Correlation Rules
| Edge Type | Source Node | Target Node | Deterministic Basis | Attributes |
|:---|:---|:---|:---|:---|
| `CONTAINS` | `domain` | `subdomain` | Database Domain-to-Subdomain foreign key hierarchy | `discovery_source` |
| `RESOLVES_TO` | `subdomain` | `ip` | `DNSRecord` (A / AAAA) observed in this `scan_run_id` | `record_type`, `ttl`, `resolver` |
| `ANNOUNCED_BY` | `ip` | `asn` | `IPObservation` matching IP & ASN in this `scan_run_id` | `asn_number`, `prefix` |
| `EXPOSES` | `subdomain` / `domain` | `service` | `ServiceExposure` recorded for asset in this `scan_run_id` | `port`, `protocol`, `service_name` |
| `USES_TECHNOLOGY` | `subdomain` / `service` | `technology` | `Technology` fingerprint detected in this `scan_run_id` | `name`, `version`, `cpe`, `confidence` |
| `AFFECTED_BY` | `technology` | `vulnerability` | `TechnologyVulnerability` correlation for observed tech | `cve_id`, `severity`, `match_confidence` |
| `HAS_CERTIFICATE` | `subdomain` | `certificate` | `subdomain_certificates` association for this `scan_run_id` | `subject_cn`, `issuer`, `is_expired` |

---

## 4. Strict "No-Invention" Correlation Policy

1. **No direct Subdomain -> Vulnerability shortcuts**: Vulnerabilities are only linked through the verified Technology component that hosts them (`Subdomain -> Technology -> Vulnerability`).
2. **No inferred domain relationships**: Two domains are NEVER inferred to be related or co-owned merely because they share a public IP, CDN, cloud provider, or ASN.
3. **No probabilistic graph edges**: All relationships are backed by explicit, stored database observations with cryptographic evidence provenance.

---

## 5. Historical ScanRun Isolation & Idempotency

### A. Point-in-Time Isolation
Each scan run maintains an isolated snapshot of observations:
- **ScanRun 1**: `api.example.com` resolves to `192.0.2.10` (ASN 100).
- **ScanRun 2**: `api.example.com` resolves to `198.51.100.20` (ASN 200).
- Requesting `GET /api/investigations/{id}/graph?scan_run_id=<ScanRun 1>` returns strictly `192.0.2.10` and `ASN 100`.
- Subsequent scan runs never overwrite or alter the historical relationship graph of earlier scan runs.

### B. Idempotency & AssetRelationship Persistence
Asset-to-asset edges are persisted in `asset_relationships` with composite unique constraint `uq_investigation_scan_run_asset_relationship` across:
`("investigation_id", "scan_run_id", "source_asset_id", "target_asset_id", "relationship_type")`
Repeated calls to the graph builder produce identical nodes, edges, and statistics without creating duplicate database records.

---

## 6. API Reference

### `GET /api/investigations/{investigation_id}/graph`

Retrieves the complete attack-surface relationship graph.

#### Query Parameters:
- `scan_run_id` *(UUID, optional)*: Specific point-in-time scan run ID. If omitted, defaults to the latest scan run.
- `node_type` *(List[str], optional)*: Filter nodes by type (e.g. `?node_type=technology&node_type=vulnerability`).
- `relationship_type` *(List[str], optional)*: Filter edges by relationship (e.g. `?relationship_type=RESOLVES_TO`).

#### Example Response:
```json
{
  "investigation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "scan_run_id": "4a2c1de1-ffcd-4bed-d094-cf06be94f063",
  "scan_run_number": 1,
  "target_domain": "example.com",
  "nodes": [
    {
      "id": "domain:7831f24d-0e42-4f35-9615-9509df6389f4",
      "type": "domain",
      "label": "example.com",
      "asset_id": "7831f24d-0e42-4f35-9615-9509df6389f4",
      "entity_id": "8e3646f2-bb4e-4f05-87d4-06175e119429",
      "metadata": {
        "domain_name": "example.com",
        "registrar": "MarkMonitor Inc.",
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "status": ["clientTransferProhibited"]
      }
    },
    {
      "id": "subdomain:b5853b0e-11f8-45b6-b51f-5fc0c9a4140a",
      "type": "subdomain",
      "label": "api.example.com",
      "asset_id": "b5853b0e-11f8-45b6-b51f-5fc0c9a4140a",
      "entity_id": "060d4b1a-8c9e-4c74-9407-28d844517b6a",
      "metadata": {
        "subdomain_name": "api.example.com",
        "is_resolving": true,
        "discovery_source": "crt.sh"
      }
    },
    {
      "id": "ip:b8fe9024-5d55-46eb-8e54-ccb913ea2fbc",
      "type": "ip",
      "label": "198.51.100.25",
      "asset_id": "b8fe9024-5d55-46eb-8e54-ccb913ea2fbc",
      "entity_id": "e4983e20-7f24-4f37-97fe-f1b95ce702e1",
      "metadata": {
        "ip_address": "198.51.100.25",
        "ip_version": 4,
        "reverse_dns": "api-edge.example.com",
        "country": "US",
        "organization": "GraphCloud LLC"
      }
    },
    {
      "id": "asn:1f67f2bc-8153-48ee-a6a3-2c6c39f1969a",
      "type": "asn",
      "label": "AS64500 (GraphCloud Networks)",
      "entity_id": "1f67f2bc-8153-48ee-a6a3-2c6c39f1969a",
      "metadata": {
        "asn_number": 64500,
        "name": "GraphCloud Networks",
        "country": "US",
        "allocated_prefix": "198.51.100.0/24"
      }
    }
  ],
  "edges": [
    {
      "id": "edge:domain:7831f24d-0e42-4f35-9615-9509df6389f4->subdomain:b5853b0e-11f8-45b6-b51f-5fc0c9a4140a:CONTAINS",
      "source": "domain:7831f24d-0e42-4f35-9615-9509df6389f4",
      "target": "subdomain:b5853b0e-11f8-45b6-b51f-5fc0c9a4140a",
      "relationship_type": "CONTAINS",
      "scan_run_id": "4a2c1de1-ffcd-4bed-d094-cf06be94f063",
      "evidence_id": null,
      "confidence": 1.0,
      "attributes": {
        "discovery_source": "crt.sh"
      }
    },
    {
      "id": "edge:subdomain:b5853b0e-11f8-45b6-b51f-5fc0c9a4140a->ip:b8fe9024-5d55-46eb-8e54-ccb913ea2fbc:RESOLVES_TO",
      "source": "subdomain:b5853b0e-11f8-45b6-b51f-5fc0c9a4140a",
      "target": "ip:b8fe9024-5d55-46eb-8e54-ccb913ea2fbc",
      "relationship_type": "RESOLVES_TO",
      "scan_run_id": "4a2c1de1-ffcd-4bed-d094-cf06be94f063",
      "evidence_id": null,
      "confidence": 1.0,
      "attributes": {
        "record_type": "A",
        "ttl": 300,
        "resolver": "1.1.1.1"
      }
    }
  ],
  "statistics": {
    "node_count": 4,
    "edge_count": 2,
    "nodes_by_type": {
      "domain": 1,
      "subdomain": 1,
      "ip": 1,
      "asn": 1
    },
    "edges_by_type": {
      "CONTAINS": 1,
      "RESOLVES_TO": 1
    }
  }
}
```

---

## 7. Security Model & RBAC

1. **Authentication Required**: All graph endpoints require valid JWT authentication.
2. **Investigation RBAC Enforcement**: Only the owner analyst or platform administrators can view graph data for an investigation (`403 Forbidden` for other users).
3. **Cross-Investigation Leakage Prevention**: If a user requests an investigation graph with a `scan_run_id` that belongs to a different investigation, the request is strictly rejected with `400 Bad Request`.
4. **No Remote Code / SQL Injection Surface**: Graph construction is 100% parameter-bound through SQLAlchemy ORM queries with zero dynamic string SQL execution.

---

## 8. Important Limitations & Operational Disclaimers

> [!IMPORTANT]
> The Attack Surface Relationship Graph represents **observed and correlated technical relationships** extracted from passive OSINT intelligence and standard DNS/HTTP observation.
>
> The graph **DOES NOT**:
> 1. Prove exploitability of any vulnerability.
> 2. Prove host compromise or malicious infiltration.
> 3. Prove attacker movement or lateral lateral traversal capability.
> 4. Imply organizational ownership over shared third-party infrastructure (e.g. Cloudflare, AWS, multi-tenant IP spaces, shared ASNs).
> 5. Imply malicious intent on behalf of any entity.
