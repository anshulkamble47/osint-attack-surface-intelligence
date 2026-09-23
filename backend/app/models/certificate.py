"""Certificate Transparency and TLS Certificate models."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    Uuid,
    ForeignKey,
    JSON,
    Column,
    Table,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.connection import Base

# Association table for Subdomain <-> Certificate many-to-many relationship
subdomain_certificates = Table(
    "subdomain_certificates",
    Base.metadata,
    Column(
        "subdomain_id",
        Uuid(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "certificate_id",
        Uuid(as_uuid=True),
        ForeignKey("certificates.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "scan_run_id",
        Uuid(as_uuid=True),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    ),
    Column(
        "observed_at",
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    ),
)


class Certificate(Base):
    """Discovered SSL/TLS certificates and CT log records."""

    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    fingerprint_sha256: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    san_list: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    valid_to: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    is_expired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ct_log_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    raw_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    subdomains = relationship(
        "Subdomain",
        secondary=subdomain_certificates,
        back_populates="certificates",
    )

    def __repr__(self) -> str:
        return f"<Certificate CN={self.subject_cn} issuer={self.issuer}>"
