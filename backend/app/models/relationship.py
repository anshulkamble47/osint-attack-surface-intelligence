"""Asset relationship and attack surface graph correlation models."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from sqlalchemy import (
    String,
    Float,
    DateTime,
    Uuid,
    ForeignKey,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class AssetRelationship(Base):
    """
    Interconnected relationship edge between two assets forming the Attack Surface Graph.
    Connects: Domain -> Subdomain -> IP -> ASN -> Technology -> CVE -> Finding.
    """

    __tablename__ = "asset_relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # has_subdomain, resolves_to, belongs_to_asn, uses_certificate, exposes_technology, associated_with_cve, has_finding
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    attributes: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # port, protocol, record_type
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Unique constraint preventing duplicate graph edges in the same investigation
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_investigation_asset_relationship",
        ),
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="relationships")
    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    target_asset = relationship("Asset", foreign_keys=[target_asset_id])

    def __repr__(self) -> str:
        return f"<AssetRelationship {self.relationship_type} ({self.source_asset_id} -> {self.target_asset_id})>"
