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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class ChangeRecord(Base):
    """
    Change record computed between successive scans (ADDED, REMOVED, MODIFIED).
    Enables monitoring of attack surface evolution over time.
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
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    change_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # ADDED, REMOVED, MODIFIED
    field_name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # ip_resolution, technology, open_port, cert_expiry
    old_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    new_value: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="change_records")
    current_scan = relationship(
        "ScanRun", foreign_keys=[current_scan_id], back_populates="current_changes"
    )
    previous_scan = relationship("ScanRun", foreign_keys=[previous_scan_id])
    asset = relationship("Asset")

    def __repr__(self) -> str:
        return f"<ChangeRecord type={self.change_type} field={self.field_name} asset={self.asset_id}>"


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
    )  # asset_discovered, ip_changed, technology_detected, cert_observed
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
