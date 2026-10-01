"""Change monitoring, baseline diffing, and audit timeline models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    String,
    Text,
    DateTime,
    Uuid,
    ForeignKey,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class ChangeRecord(Base):
    """
    Change record computed between successive scans (ADDED, REMOVED, MODIFIED).
    Enables deterministic monitoring of attack surface evolution over time.
    """

    __tablename__ = "change_records"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    current_scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    change_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # ADDED, REMOVED, MODIFIED
    field_name: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # subdomain, domain, dns_record, ip_observation, service_exposure, technology, vulnerability, certificate, asset_relationship, finding
    category: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True, index=True
    )  # subdomain, domain, dns_record, ip_observation, service_exposure, technology, vulnerability, certificate, asset_relationship, finding
    entity_key: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )  # Stable identity key for deterministic comparison
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    old_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    new_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    evidence_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Unique constraint preventing duplicate change records for the same comparison
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "previous_scan_id",
            "current_scan_id",
            "change_type",
            "field_name",
            "entity_key",
            name="uq_change_records_comparison",
        ),
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="change_records")
    current_scan = relationship(
        "ScanRun", foreign_keys=[current_scan_id], back_populates="current_changes"
    )
    previous_scan = relationship("ScanRun", foreign_keys=[previous_scan_id])
    asset = relationship("Asset")
    evidence = relationship("Evidence")

    @property
    def baseline_scan_run_id(self) -> Optional[uuid.UUID]:
        """Alias for previous_scan_id representing baseline comparison ScanRun."""
        return self.previous_scan_id

    @property
    def current_scan_run_id(self) -> uuid.UUID:
        """Alias for current_scan_id representing current comparison ScanRun."""
        return self.current_scan_id

    def __repr__(self) -> str:
        return f"<ChangeRecord type={self.change_type} category={self.category} key={self.entity_key}>"


class TimelineEvent(Base):
    """Investigation audit log and historical discovery timeline."""

    __tablename__ = "timeline_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # asset_discovered, ip_changed, technology_detected, cert_observed, change_detected
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="timeline_events")
    asset = relationship("Asset")

    def __repr__(self) -> str:
        return f"<TimelineEvent type={self.event_type} title={self.title} time={self.event_time}>"
