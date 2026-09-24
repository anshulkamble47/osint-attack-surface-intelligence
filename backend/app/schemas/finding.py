"""Pydantic schemas for Security Findings, Contextual Risk Scoring, and Evidence Intelligence."""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingAssetSummary(BaseModel):
    """Concise representation of the asset affected by a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_type: str
    value: str


class FindingTechnologySummary(BaseModel):
    """Concise representation of the technology linked to a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    category: str
    confidence: float


class FindingVulnerabilitySummary(BaseModel):
    """Concise representation of the vulnerability intelligence linked to a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str
    title: Optional[str] = None
    severity: str
    cvss_v3_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    source: str = "NVD"


class FindingEvidenceSummary(BaseModel):
    """Concise representation of cryptographic evidence supporting a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    reference_code: str
    evidence_type: str
    source: str
    sha256_hash: str
    collected_at: datetime


class RiskFactorDetail(BaseModel):
    """Transparent, explainable risk scoring factor detail."""

    base_score: int = Field(..., description="Base score derived directly from CVSS or category severity (0-100)")
    base_factor: str = Field(..., description="Explanation of base score calculation")
    cisa_kev_adjustment: int = Field(0, description="Adjustment for CISA KEV listing (+15)")
    cisa_kev_reason: Optional[str] = Field(None, description="Explanation of CISA KEV adjustment")
    exposure_adjustment: int = Field(0, description="Adjustment for external internet reachability (+10)")
    exposure_reason: Optional[str] = Field(None, description="Explanation of exposure adjustment")
    confidence_adjustment: int = Field(0, description="Adjustment based on fingerprint match confidence (+5 to -10)")
    confidence_reason: Optional[str] = Field(None, description="Explanation of confidence adjustment")
    final_score: int = Field(..., description="Bounded contextual platform risk score (0-100)")
    risk_category: str = Field(..., description="Contextual platform risk level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")


class FindingResponse(BaseModel):
    """Detailed response for a security finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    reference_code: str
    investigation_id: uuid.UUID
    scan_run_id: Optional[uuid.UUID] = None
    asset_id: uuid.UUID
    technology_id: Optional[uuid.UUID] = None
    vulnerability_id: Optional[uuid.UUID] = None
    title: str
    description: str
    category: str
    finding_type: str
    severity: str
    status: str
    context_score: int = Field(..., description="Contextual platform risk score (0-100)")
    risk_score: int = Field(..., description="Alias for context_score (0-100)")
    risk_category: str = Field(..., description="Platform risk level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    cvss_score: Optional[float] = Field(None, description="Original CVSS base score from vulnerability intelligence")
    is_kev: bool = Field(False, description="Whether the CVE is cataloged in CISA Known Exploited Vulnerabilities")
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    risk_factors: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    recommendation: str
    is_verified: bool = False
    asset: Optional[FindingAssetSummary] = None
    technology: Optional[FindingTechnologySummary] = None
    vulnerability: Optional[FindingVulnerabilitySummary] = None
    evidence_items: List[FindingEvidenceSummary] = Field(default_factory=list)
    created_at: datetime
    updated_at: Optional[datetime] = None


class FindingStatusUpdateRequest(BaseModel):
    """Request schema for updating finding lifecycle status."""

    status: str = Field(..., pattern="^(open|acknowledged|resolved|suppressed)$", description="Target lifecycle state")


class GenerateFindingsResponse(BaseModel):
    """Response returned when findings generation is triggered for an investigation."""

    investigation_id: uuid.UUID
    scan_run_id: Optional[uuid.UUID] = None
    scan_run_number: Optional[int] = None
    findings_generated: int
    findings_updated: int
    findings_total: int
    severity_breakdown: Dict[str, int]
    risk_category_breakdown: Dict[str, int]
    findings: List[FindingResponse]
    completed_at: datetime
    note: str


class FindingListResponse(BaseModel):
    """Unified collection response for investigation findings with summary statistics."""

    investigation_id: uuid.UUID
    scan_run_id: Optional[uuid.UUID] = None
    total: int
    severity_breakdown: Dict[str, int]
    risk_category_breakdown: Dict[str, int]
    findings: List[FindingResponse]
