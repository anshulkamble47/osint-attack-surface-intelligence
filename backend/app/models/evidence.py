"""Cryptographic evidence and provenance models."""

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    String,
    Text,
    Boolean,
    DateTime,
    Uuid,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base


class Evidence(Base):
    """
    Evidence record preserving raw observations with cryptographic SHA-256 integrity hashes.
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    reference_code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )  # EV-00031
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
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scan_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # ct_log, dns_query, http_headers, nvd_record, rdap
    source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # crt.sh, 8.8.8.8, NVD API
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # 64-char hex string
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    verified_integrity: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # Relationships
    investigation = relationship("Investigation", back_populates="evidence_items")
    scan_run = relationship("ScanRun", back_populates="evidence_items")
    asset = relationship("Asset", back_populates="evidence_items")
    finding = relationship("Finding", back_populates="evidence_items")

    @classmethod
    def compute_sha256(cls, payload: str) -> str:
        """Compute SHA-256 hash for raw payload string."""
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify_hash(self) -> bool:
        """Check whether the stored hash matches the current raw payload."""
        return self.sha256_hash == self.compute_sha256(self.raw_payload)

    def __repr__(self) -> str:
        return f"<Evidence code={self.reference_code} type={self.evidence_type} hash={self.sha256_hash[:12]}...>"
