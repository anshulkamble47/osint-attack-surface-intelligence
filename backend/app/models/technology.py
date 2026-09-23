"""Technology fingerprinting and TechnologyVulnerability correlation models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String,
    Text,
    Float,
    DateTime,
    Uuid,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Technology(Base):
    """Observed web technology fingerprint on an asset or service."""

    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("service_exposures.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # nginx, Apache, React, WordPress
    version: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # 1.18.0, 2.4.41
    cpe: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # cpe:2.3:a:apache:http_server:2.4.41:...
    category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # web_server, framework, cms, js_library
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.8
    )  # 0.0 - 1.0
    evidence_source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # headers, meta_generator, script_src, cookie
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    asset = relationship("Asset", back_populates="technologies")
    service = relationship("ServiceExposure", back_populates="technologies")
    scan_run = relationship("ScanRun", back_populates="technologies")
    vulnerability_correlations = relationship(
        "TechnologyVulnerability",
        back_populates="technology",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Technology {self.name} v={self.version} confidence={self.confidence}>"


class TechnologyVulnerability(Base):
    """
    Correlation link between an observed technology and vulnerability intelligence.
    Enforces project principle: distinguish Observed version from Potential CVE match.
    """

    __tablename__ = "technology_vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    technology_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("technologies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    match_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)
    verification_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="requires_verification", index=True
    )  # requires_verification, potential, verified, false_positive
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Unique constraint preventing duplicate link
    __table_args__ = (
        UniqueConstraint(
            "technology_id",
            "vulnerability_id",
            name="uq_technology_vulnerability",
        ),
    )

    # Relationships
    technology = relationship(
        "Technology", back_populates="vulnerability_correlations"
    )
    vulnerability = relationship(
        "Vulnerability", back_populates="technology_correlations"
    )

    def __repr__(self) -> str:
        return f"<TechnologyVulnerability tech_id={self.technology_id} status={self.verification_status}>"
