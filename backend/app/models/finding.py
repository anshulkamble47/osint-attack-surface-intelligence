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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Finding(Base):
    """
    Explainable security finding with transparent context scoring and recommendations.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    reference_code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )  # F-0001
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # vulnerability, missing_header, exposed_service, expired_cert
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    context_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )  # 0 - 100
    score_breakdown: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )  # {exposure: 25, tech_confidence: 20, cve_severity: 30, recency: 15, sources: 10}
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open", index=True
    )  # open, acknowledged, resolved, false_positive
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    evidence_items = relationship(
        "Evidence", back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Finding code={self.reference_code} score={self.context_score} severity={self.severity}>"
