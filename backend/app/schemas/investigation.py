"""Pydantic schemas for Target, Investigation, and Certificate Transparency operations."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator
from backend.app.utils.domain import normalize_domain, is_valid_domain


class InvestigationCreateRequest(BaseModel):
    """Schema for creating a new authorized investigation assessment."""
    name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Investigation title or name",
        examples=["Q1 External Attack Surface Review"],
    )
    target_domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Target primary domain or FQDN to assess",
        examples=["example.com", "https://example.com/"],
    )
    organization: Optional[str] = Field(
        None,
        max_length=255,
        description="Target organization name",
        examples=["Acme Corporation"],
    )
    description: Optional[str] = Field(
        None,
        max_length=2000,
        description="Investigation scope or context notes",
    )
    scan_options: Dict[str, Any] = Field(
        default_factory=lambda: {"ct_enabled": True},
        description="Scan execution configuration options",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("target_domain")
    @classmethod
    def validate_and_normalize_target_domain(cls, v: str) -> str:
        normalized = normalize_domain(v)
        if not normalized or not is_valid_domain(normalized):
            raise ValueError(
                f"Invalid target domain: '{v}'. Must be a valid public domain name (e.g., 'example.com')."
            )
        return normalized


class TargetResponse(BaseModel):
    """Safe Target domain response schema."""
    id: uuid.UUID
    name: str
    primary_domain: str
    organization: Optional[str] = None
    description: Optional[str] = None
    is_authorized: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationResponse(BaseModel):
    """Safe Investigation assessment response schema."""
    id: uuid.UUID
    reference_code: str
    target_id: uuid.UUID
    target_domain: str
    title: str
    status: str
    scan_options: Dict[str, Any]
    created_by_id: Optional[uuid.UUID] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CertificateSummaryResponse(BaseModel):
    """Discovered TLS certificate observation summary."""
    fingerprint_sha256: str = Field(
        ...,
        description=(
            "Unique certificate SHA-256 identifier. For passive CT records, this is a deterministic "
            "hash computed from (issuer + serial_number); for active TLS scans, it represents the raw DER digest."
        ),
    )
    subject_cn: str
    issuer: str
    san_list: List[str]
    valid_from: datetime
    valid_to: datetime
    is_expired: bool
    ct_log_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class CTDiscoveryResponse(BaseModel):
    """Structured response returned by Certificate Transparency passive discovery."""
    investigation_id: uuid.UUID
    target_domain: str
    scan_run_id: uuid.UUID
    source: str = "crt.sh"
    hostname_count: int
    certificate_count: int
    hostnames: List[str]
    certificates: List[CertificateSummaryResponse]
    discovery_timestamp: datetime
    note: str = (
        "Hostnames are candidate assets discovered from CT logs. "
        "Active DNS reachability validation occurs in Stage 3B."
    )


class AssetSummaryResponse(BaseModel):
    """Discovered attack-surface asset summary."""
    id: uuid.UUID
    asset_type: str
    value: str
    is_active: bool
    confidence: float
    source: str
    risk_score: int
    tags: List[str]
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DNSRecordSummaryResponse(BaseModel):
    """Observed DNS resource record response schema."""
    id: uuid.UUID
    subdomain_id: uuid.UUID
    record_type: str
    value: str
    ttl: Optional[int] = None
    resolver: str = "system_resolver"
    collected_at: datetime
    scan_run_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(from_attributes=True)


class ServiceExposureSummaryResponse(BaseModel):
    """Observed HTTP/HTTPS service reachability response schema."""
    id: uuid.UUID
    asset_id: uuid.UUID
    port: int
    protocol: str = "tcp"
    service_name: str = "http"
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    observed_at: datetime
    scan_run_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(from_attributes=True)


class CandidateResolutionDetail(BaseModel):
    """Individual candidate resolution and reachability summary."""
    hostname: str
    is_resolving: bool
    is_reachable: bool
    dns_records_count: int
    services_count: int
    dns_records: List[DNSRecordSummaryResponse] = Field(default_factory=list)
    service_exposures: List[ServiceExposureSummaryResponse] = Field(default_factory=list)
    error: Optional[str] = None


class DNSReachabilityResponse(BaseModel):
    """Structured response returned by Active DNS Resolution & Reachability Probing (Stage 3B)."""
    investigation_id: uuid.UUID
    scan_run_id: uuid.UUID
    target_domain: str
    candidates_processed: int
    resolved: int
    not_resolved: int
    reachable: int
    unreachable: int
    dns_records_discovered: int
    services_discovered: int
    results: List[CandidateResolutionDetail] = Field(default_factory=list)
    completed_at: datetime
    note: str = (
        "Active DNS records and HTTP/HTTPS reachability observations persisted. "
        "IP/ASN enrichment and detailed technology fingerprinting occur in subsequent stages."
    )


class ASNSummaryResponse(BaseModel):
    """Autonomous System Number intelligence summary."""
    id: Optional[uuid.UUID] = None
    asn_number: int
    name: str
    country: Optional[str] = None
    allocated_prefix: Optional[str] = None
    ip_count: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class RDAPSummaryResponse(BaseModel):
    """Normalized RDAP network registration observation summary."""
    network_name: Optional[str] = None
    handle: Optional[str] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    cidr: Optional[str] = None
    country: Optional[str] = None
    organization: Optional[str] = None
    status: List[str] = Field(default_factory=list)
    registration_date: Optional[datetime] = None
    last_changed_date: Optional[datetime] = None


class IPAddressSummaryResponse(BaseModel):
    """Normalized IP address asset summary."""
    id: uuid.UUID
    asset_id: uuid.UUID
    ip_address: str
    ip_version: int
    reverse_dns: Optional[str] = None
    asn_id: Optional[uuid.UUID] = None
    asn: Optional[ASNSummaryResponse] = None
    country: Optional[str] = None
    region: Optional[str] = None
    organization: Optional[str] = None
    is_active: bool = True
    last_scan_run_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(from_attributes=True)


class IPObservationSummaryResponse(BaseModel):
    """Historical IP observation summary linking an IP Address with an ASN and ScanRun."""
    id: uuid.UUID
    scan_run_id: uuid.UUID
    ip_address_id: uuid.UUID
    ip_address: Optional[str] = None
    asn_id: Optional[uuid.UUID] = None
    asn_number: Optional[int] = None
    asn_name: Optional[str] = None
    observed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IPEnrichmentDetail(BaseModel):
    """Enrichment result for an individual discovered IP address."""
    ip_address: str
    ip_version: int
    is_public: bool
    status: str  # enriched, skipped_non_public, failed, partial
    asn: Optional[ASNSummaryResponse] = None
    rdap: Optional[RDAPSummaryResponse] = None
    error: Optional[str] = None


class IPEnrichmentResponse(BaseModel):
    """Structured response returned by IP / ASN / RDAP Intelligence Enrichment (Stage 4)."""
    investigation_id: uuid.UUID
    scan_run_id: uuid.UUID
    target_domain: str
    ips_processed: int
    public_ips: int
    skipped_non_public: int
    asn_success: int
    rdap_success: int
    failed: int
    results: List[IPEnrichmentDetail] = Field(default_factory=list)
    completed_at: datetime
    note: str = (
        "IP intelligence enrichment completed. "
        "ASN and RDAP registration observations persisted and linked with ScanRun."
    )

