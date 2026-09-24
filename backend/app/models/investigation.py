"""Target, Investigation, and ScanRun models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Text, Boolean, Integer, DateTime, Uuid, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Target(Base):
    """Target organization or domain scope authorized for assessment."""

    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    primary_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigations = relationship(
        "Investigation", back_populates="target", cascade="all, delete-orphan"
    )
    assets = relationship(
        "Asset", back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Target domain={self.primary_domain} name={self.name}>"


class Investigation(Base):
    """Investigation assessment instance grouping OSINT scan runs, assets, and findings."""

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    reference_code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending", index=True
    )
    scan_options: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    target = relationship("Target", back_populates="investigations")
    created_by = relationship("User", back_populates="investigations")
    scan_runs = relationship(
        "ScanRun", back_populates="investigation", cascade="all, delete-orphan"
    )
    assets = relationship(
        "Asset", back_populates="investigation", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="investigation", cascade="all, delete-orphan"
    )
    evidence_items = relationship(
        "Evidence", back_populates="investigation", cascade="all, delete-orphan"
    )
    relationships = relationship(
        "AssetRelationship",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    change_records = relationship(
        "ChangeRecord", back_populates="investigation", cascade="all, delete-orphan"
    )
    timeline_events = relationship(
        "TimelineEvent", back_populates="investigation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Investigation code={self.reference_code} status={self.status}>"


class ScanRun(Base):
    """Point-in-time scan execution for an investigation used for historical baseline diffing."""

    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="running", index=True
    )
    total_discovered_assets: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_resolving_assets: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="scan_runs")
    current_changes = relationship(
        "ChangeRecord",
        foreign_keys="ChangeRecord.current_scan_id",
        back_populates="current_scan",
        cascade="all, delete-orphan",
    )
    last_scanned_assets = relationship(
        "Asset",
        foreign_keys="Asset.last_scan_run_id",
        back_populates="last_scan_run",
    )
    dns_records = relationship(
        "DNSRecord",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    service_exposures = relationship(
        "ServiceExposure",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    technologies = relationship(
        "Technology",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    evidence_items = relationship(
        "Evidence",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    ip_observations = relationship(
        "IPObservation",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ScanRun run={self.run_number} status={self.status}>"
