"""Asset, Domain, Subdomain, DNS, ASN, IPAddress, and ServiceExposure models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String,
    Text,
    Boolean,
    Integer,
    Float,
    DateTime,
    Uuid,
    ForeignKey,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Asset(Base):
    """
    Unified core asset registry representing any digital entity discovered
    on the attack surface (domain, subdomain, IP, certificate, service).
    """

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # domain, subdomain, ip, certificate, service
    value: Mapped[str] = mapped_column(
        String(512), nullable=False, index=True
    )  # FQDN, IP string, cert fingerprint, etc.
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # ct_log, dns, rdap, http_probe
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    last_scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    target = relationship("Target", back_populates="assets")
    investigation = relationship("Investigation", back_populates="assets")
    last_scan_run = relationship(
        "ScanRun",
        foreign_keys=[last_scan_run_id],
        back_populates="last_scanned_assets",
    )

    # One-to-one specialized asset extensions
    domain = relationship(
        "Domain",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
    )
    subdomain = relationship(
        "Subdomain",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
    )
    ip_address = relationship(
        "IPAddress",
        back_populates="asset",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # One-to-many associations
    service_exposures = relationship(
        "ServiceExposure", back_populates="asset", cascade="all, delete-orphan"
    )
    technologies = relationship(
        "Technology", back_populates="asset", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="asset", cascade="all, delete-orphan"
    )
    evidence_items = relationship(
        "Evidence", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Asset type={self.asset_type} value={self.value}>"


class Domain(Base):
    """Domain registration & RDAP registry information."""

    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    domain_name: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    registrar: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    registration_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expiration_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    nameservers: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    rdap_raw: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="domain")
    subdomains = relationship(
        "Subdomain", back_populates="domain", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Domain name={self.domain_name} registrar={self.registrar}>"


class Subdomain(Base):
    """Discovered hostname/subdomain and DNS reachability state."""

    __tablename__ = "subdomains"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subdomain_name: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    is_resolving: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )  # Distinguishes active resolving from historical/CT candidate
    discovery_source: Mapped[str] = mapped_column(
        String(100), nullable=False, default="crt.sh"
    )
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    asset = relationship("Asset", back_populates="subdomain")
    domain = relationship("Domain", back_populates="subdomains")
    dns_records = relationship(
        "DNSRecord", back_populates="subdomain", cascade="all, delete-orphan"
    )
    certificates = relationship(
        "Certificate",
        secondary="subdomain_certificates",
        back_populates="subdomains",
    )

    def __repr__(self) -> str:
        return f"<Subdomain name={self.subdomain_name} resolving={self.is_resolving}>"


class DNSRecord(Base):
    """Observed DNS resource records associated with hostnames."""

    __tablename__ = "dns_records"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    subdomain_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    record_type: Mapped[str] = mapped_column(
        String(10), nullable=False, index=True
    )  # A, AAAA, CNAME, MX, NS, TXT, SOA, PTR
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    resolver: Mapped[str] = mapped_column(
        String(100), nullable=False, default="system_resolver"
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    subdomain = relationship("Subdomain", back_populates="dns_records")
    scan_run = relationship("ScanRun", back_populates="dns_records")

    def __repr__(self) -> str:
        return f"<DNSRecord {self.record_type}={self.value}>"


class ASN(Base):
    """Autonomous System Number and routing network owner intelligence."""

    __tablename__ = "asns"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asn_number: Mapped[int] = mapped_column(
        Integer, unique=True, nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    country: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    allocated_prefix: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Relationships
    ip_addresses = relationship("IPAddress", back_populates="asn")

    def __repr__(self) -> str:
        return f"<ASN AS{self.asn_number} name={self.name}>"


class IPAddress(Base):
    """Observed IP addresses and geolocation/infrastructure details."""

    __tablename__ = "ip_addresses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False, index=True
    )
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    reverse_dns: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asn_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("asns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    country: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Relationships
    asset = relationship("Asset", back_populates="ip_address")
    asn = relationship("ASN", back_populates="ip_addresses")

    def __repr__(self) -> str:
        return f"<IPAddress ip={self.ip_address} asn={self.asn_id}>"


class ServiceExposure(Base):
    """Externally observable network service or HTTP endpoint."""

    __tablename__ = "service_exposures"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, default="tcp"
    )  # tcp / udp
    service_name: Mapped[str] = mapped_column(
        String(50), nullable=False, default="http"
    )  # http, https
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    page_title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tls_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    security_headers: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    asset = relationship("Asset", back_populates="service_exposures")
    scan_run = relationship("ScanRun", back_populates="service_exposures")
    technologies = relationship(
        "Technology", back_populates="service", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ServiceExposure port={self.port}/{self.protocol} service={self.service_name}>"
