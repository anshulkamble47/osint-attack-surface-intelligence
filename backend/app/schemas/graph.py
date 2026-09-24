"""Pydantic models and serialization schemas for Attack Surface Graph and correlation."""

import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class GraphNode(BaseModel):
    """
    Standardized node entity in the attack surface graph.
    Represents domains, subdomains, IPs, ASNs, services, technologies, vulnerabilities, and certificates.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Stable unique identifier for the node (e.g. domain:<asset_id>, ip:<asset_id>, vuln:<cve_id>)")
    type: str = Field(..., description="Entity category: domain, subdomain, ip, asn, service, technology, vulnerability, certificate")
    label: str = Field(..., description="Human-readable display label")
    asset_id: Optional[uuid.UUID] = Field(None, description="Underlying Asset UUID if this entity maps to an Asset record")
    entity_id: Optional[str] = Field(None, description="Underlying primary key / identifier of the specific entity")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Deterministic entity-specific attributes")


class GraphEdge(BaseModel):
    """
    Standardized relationship edge connecting two entities in the attack surface graph.
    Represents explicit, evidence-backed connections scoped to a ScanRun.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Stable unique edge identifier")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    relationship_type: str = Field(..., description="Explicit relationship: CONTAINS, RESOLVES_TO, ANNOUNCED_BY, EXPOSES, USES_TECHNOLOGY, AFFECTED_BY, HAS_CERTIFICATE")
    scan_run_id: Optional[uuid.UUID] = Field(None, description="ScanRun attribution for historical isolation")
    evidence_id: Optional[uuid.UUID] = Field(None, description="Cryptographic evidence reference if available")
    confidence: float = Field(1.0, description="Correlation confidence")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Relationship metadata (port, protocol, record_type, cpe, match_basis, etc.)")


class GraphStatistics(BaseModel):
    """Deterministic summary statistics for the attack surface graph."""

    model_config = ConfigDict(from_attributes=True)

    node_count: int = Field(0, description="Total number of nodes in the graph")
    edge_count: int = Field(0, description="Total number of edges in the graph")
    nodes_by_type: Dict[str, int] = Field(default_factory=dict, description="Count of nodes grouped by entity type")
    edges_by_type: Dict[str, int] = Field(default_factory=dict, description="Count of edges grouped by relationship type")


class GraphResponse(BaseModel):
    """Unified API response representing the full Attack Surface Relationship Graph."""

    model_config = ConfigDict(from_attributes=True)

    investigation_id: uuid.UUID = Field(..., description="Investigation UUID")
    scan_run_id: Optional[uuid.UUID] = Field(None, description="ScanRun UUID (None if no scan runs exist)")
    scan_run_number: Optional[int] = Field(None, description="Point-in-time scan run number")
    target_domain: str = Field(..., description="Target root domain")
    nodes: List[GraphNode] = Field(default_factory=list, description="List of graph nodes")
    edges: List[GraphEdge] = Field(default_factory=list, description="List of graph edges")
    statistics: GraphStatistics = Field(..., description="Descriptive graph statistics")
