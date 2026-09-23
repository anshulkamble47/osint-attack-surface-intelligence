"""Consolidated models package exporting all SQLAlchemy domain entities."""

from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import (
    Asset,
    Domain,
    Subdomain,
    DNSRecord,
    ASN,
    IPAddress,
    ServiceExposure,
)
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.finding import Finding
from backend.app.models.evidence import Evidence
from backend.app.models.relationship import AssetRelationship
from backend.app.models.change import ChangeRecord, TimelineEvent

__all__ = [
    "User",
    "Target",
    "Investigation",
    "ScanRun",
    "Asset",
    "Domain",
    "Subdomain",
    "DNSRecord",
    "ASN",
    "IPAddress",
    "ServiceExposure",
    "Certificate",
    "subdomain_certificates",
    "Technology",
    "TechnologyVulnerability",
    "Vulnerability",
    "Finding",
    "Evidence",
    "AssetRelationship",
    "ChangeRecord",
    "TimelineEvent",
]
