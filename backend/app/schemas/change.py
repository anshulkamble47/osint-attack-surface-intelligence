"""Pydantic schemas for Attack Surface Monitoring & Change Detection."""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ChangeRecordResponse(BaseModel):
    """Detailed representation of a single deterministic change record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_id: uuid.UUID
    baseline_scan_run_id: Optional[uuid.UUID] = Field(None, description="Baseline point-in-time ScanRun ID")
    current_scan_run_id: uuid.UUID = Field(..., description="Current/comparison point-in-time ScanRun ID")
    asset_id: Optional[uuid.UUID] = None
    asset_value: Optional[str] = None
    change_type: str = Field(..., description="ADDED, REMOVED, or MODIFIED")
    field_name: str = Field(..., description="Specific tracked field or observable property")
    category: str = Field(..., description="Observable entity category (subdomain, dns_record, service_exposure, technology, etc.)")
    entity_key: Optional[str] = Field(None, description="Stable logical identity key for the tracked entity")
    description: Optional[str] = Field(None, description="Human-readable explanation of what changed")
    old_value: Optional[Dict[str, Any]] = Field(None, description="Baseline observable state")
    new_value: Optional[Dict[str, Any]] = Field(None, description="Current observable state")
    evidence_id: Optional[uuid.UUID] = None
    evidence_hash: Optional[str] = None
    detected_at: datetime


class CompareScanRunsRequest(BaseModel):
    """Request payload to trigger point-in-time ScanRun comparison."""

    baseline_scan_run_id: Optional[uuid.UUID] = Field(None, description="Optional baseline ScanRun ID (defaults to previous completed scan)")
    current_scan_run_id: Optional[uuid.UUID] = Field(None, description="Optional current ScanRun ID (defaults to latest completed scan)")


class ComparisonSummaryResponse(BaseModel):
    """Response returned when a ScanRun comparison is executed."""

    investigation_id: uuid.UUID
    baseline_scan_run_id: Optional[uuid.UUID] = None
    current_scan_run_id: uuid.UUID
    baseline_scan_run_number: Optional[int] = None
    current_scan_run_number: Optional[int] = None
    total_changes: int
    added_count: int
    removed_count: int
    modified_count: int
    changes_by_category: Dict[str, int]
    changes_by_type: Dict[str, int]
    changes: List[ChangeRecordResponse]
    compared_at: datetime
    message: str


class ChangeListResponse(BaseModel):
    """Response returned when querying and filtering investigation change records."""

    investigation_id: uuid.UUID
    baseline_scan_run_id: Optional[uuid.UUID] = None
    current_scan_run_id: Optional[uuid.UUID] = None
    total: int
    added_count: int
    removed_count: int
    modified_count: int
    changes_by_category: Dict[str, int]
    changes: List[ChangeRecordResponse]
