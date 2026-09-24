"""Security finding, contextual scoring, and explainability models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    String,
    Text,
    Boolean,
    Integer,
    DateTime,
    Uuid,
    ForeignKey,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Finding(Base):
    """
    Explainable security finding with transparent context scoring and recommendations.
    Represents an evidence-backed security condition associated with an observed asset.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    reference_code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )  # F-INV-20260924-001-0001
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    technology_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("technologies.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    vulnerability_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # vulnerability, security_header, tls_security, service_exposure, configuration
    finding_type: Mapped[str] = mapped_column(
        String(50), nullable=False, default="VULNERABILITY", index=True
    )  # VULNERABILITY, SECURITY_HEADER, TLS_SECURITY, SERVICE_EXPOSURE, CONFIGURATION
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    context_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )  # 0 - 100 (Platform Contextual Risk Score)
    score_breakdown: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # Structured factor explanation
    risk_factors: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # {base_score, cisa_kev, exposure, confidence, etc.}
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open", index=True
    )  # open, acknowledged, resolved, suppressed
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

    # Unique constraint preventing duplicate finding records in the same scan run
    __table_args__ = (
        UniqueConstraint(
            "investigation_id",
            "scan_run_id",
            "asset_id",
            "category",
            "title",
            name="uq_investigation_scan_run_finding",
        ),
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    technology = relationship("Technology")
    vulnerability = relationship("Vulnerability")
    evidence_items = relationship(
        "Evidence", back_populates="finding", cascade="all, delete-orphan"
    )

    @property
    def risk_score(self) -> int:
        """Alias for context_score representing platform contextual risk."""
        return self.context_score

    def __repr__(self) -> str:
        return f"<Finding code={self.reference_code} type={self.finding_type} score={self.context_score} severity={self.severity}>"
