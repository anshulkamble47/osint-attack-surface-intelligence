"""Deterministic Attack Surface Monitoring & Change Detection Service."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set
from sqlalchemy import select, and_, func, or_
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.investigation import Investigation, ScanRun
from backend.app.models.asset import Asset, Subdomain, Domain, DNSRecord, IPAddress, ASN, IPObservation, ServiceExposure
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.relationship import AssetRelationship
from backend.app.models.finding import Finding
from backend.app.models.change import ChangeRecord, TimelineEvent
from backend.app.models.evidence import Evidence
from backend.app.schemas.change import (
    ChangeRecordResponse,
    ComparisonSummaryResponse,
    ChangeListResponse,
)


class ChangeDetectionService:
    """
    Deterministic Attack Surface Monitoring & Change Detection Service.
    Compares two point-in-time ScanRuns and computes explicit, evidence-backed ADDED, REMOVED, and MODIFIED records.
    Guarantees:
    1. Historical ScanRun isolation (never mutates past scan runs)
    2. Deterministic logical identities across all observation types
    3. Idempotent comparison execution (no duplicate ChangeRecords)
    4. Explicit authorization & investigation boundary checks
    """

    def compare_scan_runs(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_scan_run_id: Optional[uuid.UUID] = None,
        current_scan_run_id: Optional[uuid.UUID] = None,
    ) -> ComparisonSummaryResponse:
        """
        Execute deterministic comparison between baseline and current ScanRuns.
        If ScanRun IDs are omitted, resolves previous completed scan vs latest completed scan.
        """
        investigation = db.get(Investigation, investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")

        # 1. Resolve Baseline and Current ScanRuns
        baseline_scan, current_scan = self._resolve_scan_runs(
            db=db,
            investigation_id=investigation_id,
            baseline_scan_run_id=baseline_scan_run_id,
            current_scan_run_id=current_scan_run_id,
        )

        # Edge case: Same ScanRun compared with itself produces exactly 0 changes
        if baseline_scan and current_scan and baseline_scan.id == current_scan.id:
            now_utc = datetime.now(timezone.utc)
            return ComparisonSummaryResponse(
                investigation_id=investigation_id,
                baseline_scan_run_id=baseline_scan.id,
                current_scan_run_id=current_scan.id,
                baseline_scan_run_number=baseline_scan.run_number,
                current_scan_run_number=current_scan.run_number,
                total_changes=0,
                added_count=0,
                removed_count=0,
                modified_count=0,
                changes_by_category={},
                changes_by_type={},
                changes=[],
                compared_at=now_utc,
                message="Baseline and Current ScanRuns are identical. No differences observed.",
            )

        now_utc = datetime.now(timezone.utc)
        baseline_id = baseline_scan.id if baseline_scan else None
        current_id = current_scan.id

        # 2. Fetch existing ChangeRecords for idempotency
        existing_query = select(ChangeRecord).where(
            ChangeRecord.investigation_id == investigation_id,
            ChangeRecord.current_scan_id == current_id,
        )
        if baseline_id:
            existing_query = existing_query.where(ChangeRecord.previous_scan_id == baseline_id)
        else:
            existing_query = existing_query.where(ChangeRecord.previous_scan_id.is_(None))

        existing_records = db.execute(existing_query).scalars().all()
        existing_by_key: Dict[str, ChangeRecord] = {
            f"{c.change_type}_{c.field_name}_{c.entity_key}": c for c in existing_records
        }

        changes_to_persist: List[ChangeRecord] = []

        # -------------------------------------------------------------
        # MODULE 1: SUBDOMAIN / DOMAIN ASSET CHANGES
        # -------------------------------------------------------------
        self._compare_subdomains(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 2: DNS RECORD CHANGES
        # -------------------------------------------------------------
        self._compare_dns_records(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 3: IP OBSERVATIONS & ASN ROUTING CHANGES
        # -------------------------------------------------------------
        self._compare_ip_observations(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 4: SERVICE EXPOSURES & HTTP/TLS METADATA CHANGES
        # -------------------------------------------------------------
        self._compare_service_exposures(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 5: TECHNOLOGY OBSERVATIONS & VERSION CHANGES
        # -------------------------------------------------------------
        self._compare_technologies(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 6: VULNERABILITY INTELLIGENCE & CVE CORRELATIONS
        # -------------------------------------------------------------
        self._compare_vulnerabilities(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 7: TLS CERTIFICATES
        # -------------------------------------------------------------
        self._compare_certificates(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 8: ASSET RELATIONSHIPS
        # -------------------------------------------------------------
        self._compare_relationships(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # -------------------------------------------------------------
        # MODULE 9: SECURITY FINDINGS
        # -------------------------------------------------------------
        self._compare_findings(
            db=db,
            investigation_id=investigation_id,
            baseline_id=baseline_id,
            current_id=current_id,
            existing_by_key=existing_by_key,
            changes_to_persist=changes_to_persist,
            now_utc=now_utc,
        )

        # 3. Commit changes to database
        db.commit()

        # 4. Create Audit Timeline Event
        timeline_event = TimelineEvent(
            investigation_id=investigation_id,
            event_type="monitoring_comparison",
            title=f"Monitoring Comparison: Scan #{baseline_scan.run_number if baseline_scan else 'Initial'} vs #{current_scan.run_number}",
            description=f"Computed {len(changes_to_persist)} attack surface change records.",
            event_time=now_utc,
        )
        db.add(timeline_event)
        db.commit()

        # 5. Compile summary breakdown metrics
        added_count = 0
        removed_count = 0
        modified_count = 0
        changes_by_cat: Dict[str, int] = {}
        changes_by_type: Dict[str, int] = {}
        serialized_changes: List[ChangeRecordResponse] = []

        for c in changes_to_persist:
            db.refresh(c)
            if c.change_type == "ADDED":
                added_count += 1
            elif c.change_type == "REMOVED":
                removed_count += 1
            elif c.change_type == "MODIFIED":
                modified_count += 1

            cat = c.category or c.field_name
            changes_by_cat[cat] = changes_by_cat.get(cat, 0) + 1
            changes_by_type[c.change_type] = changes_by_type.get(c.change_type, 0) + 1
            serialized_changes.append(self._serialize_change(c))

        return ComparisonSummaryResponse(
            investigation_id=investigation_id,
            baseline_scan_run_id=baseline_id,
            current_scan_run_id=current_id,
            baseline_scan_run_number=baseline_scan.run_number if baseline_scan else None,
            current_scan_run_number=current_scan.run_number,
            total_changes=len(changes_to_persist),
            added_count=added_count,
            removed_count=removed_count,
            modified_count=modified_count,
            changes_by_category=changes_by_cat,
            changes_by_type=changes_by_type,
            changes=serialized_changes,
            compared_at=now_utc,
            message=(
                f"Successfully compared ScanRun #{baseline_scan.run_number if baseline_scan else 1} "
                f"and ScanRun #{current_scan.run_number}: {len(changes_to_persist)} changes detected."
            ),
        )

    def list_investigation_changes(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_scan_run_id: Optional[uuid.UUID] = None,
        current_scan_run_id: Optional[uuid.UUID] = None,
        change_type: Optional[str] = None,
        category: Optional[str] = None,
        asset_id: Optional[uuid.UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> ChangeListResponse:
        """Query and filter computed change records for an investigation."""
        query = select(ChangeRecord).where(ChangeRecord.investigation_id == investigation_id)

        if baseline_scan_run_id:
            query = query.where(ChangeRecord.previous_scan_id == baseline_scan_run_id)
        if current_scan_run_id:
            query = query.where(ChangeRecord.current_scan_id == current_scan_run_id)
        if change_type:
            query = query.where(ChangeRecord.change_type == change_type.upper())
        if category:
            query = query.where(
                or_(
                    ChangeRecord.category == category.lower(),
                    ChangeRecord.field_name == category.lower(),
                )
            )
        if asset_id:
            query = query.where(ChangeRecord.asset_id == asset_id)

        query = query.order_by(ChangeRecord.detected_at.desc(), ChangeRecord.id.asc())
        all_matches = db.execute(query).scalars().all()

        added_count = sum(1 for c in all_matches if c.change_type == "ADDED")
        removed_count = sum(1 for c in all_matches if c.change_type == "REMOVED")
        modified_count = sum(1 for c in all_matches if c.change_type == "MODIFIED")

        changes_by_cat: Dict[str, int] = {}
        for c in all_matches:
            cat = c.category or c.field_name
            changes_by_cat[cat] = changes_by_cat.get(cat, 0) + 1

        paginated = all_matches[offset : offset + limit]
        serialized = [self._serialize_change(c) for c in paginated]

        return ChangeListResponse(
            investigation_id=investigation_id,
            baseline_scan_run_id=baseline_scan_run_id,
            current_scan_run_id=current_scan_run_id,
            total=len(all_matches),
            added_count=added_count,
            removed_count=removed_count,
            modified_count=modified_count,
            changes_by_category=changes_by_cat,
            changes=serialized,
        )

    # -------------------------------------------------------------------------
    # INTERNAL HELPER & COMPARISON METHODS
    # -------------------------------------------------------------------------

    def _resolve_scan_runs(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_scan_run_id: Optional[uuid.UUID],
        current_scan_run_id: Optional[uuid.UUID],
    ) -> Tuple[Optional[ScanRun], ScanRun]:
        """Validate or automatically resolve baseline and current ScanRuns."""
        if baseline_scan_run_id and current_scan_run_id:
            base = db.get(ScanRun, baseline_scan_run_id)
            curr = db.get(ScanRun, current_scan_run_id)
            if not base or not curr:
                raise ValueError("One or both specified ScanRuns do not exist")
            if base.investigation_id != investigation_id or curr.investigation_id != investigation_id:
                raise ValueError("ScanRun does not belong to the requested investigation")
            return base, curr

        # Auto-resolve from investigation scan history
        scans = (
            db.execute(
                select(ScanRun)
                .where(ScanRun.investigation_id == investigation_id)
                .order_by(ScanRun.run_number.asc())
            )
            .scalars()
            .all()
        )

        if not scans:
            raise ValueError(f"No ScanRuns found for investigation {investigation_id}")

        if len(scans) < 2:
            raise ValueError(
                f"At least two ScanRuns are required for monitoring comparison (found {len(scans)})"
            )

        if current_scan_run_id:
            curr = db.get(ScanRun, current_scan_run_id)
            if not curr or curr.investigation_id != investigation_id:
                raise ValueError("Current ScanRun does not belong to this investigation")
            # Baseline is previous scan run in run_number order
            idx = next((i for i, s in enumerate(scans) if s.id == curr.id), None)
            if idx is None or idx == 0:
                raise ValueError("No prior baseline ScanRun exists before the specified current scan")
            base = scans[idx - 1]
            return base, curr

        if baseline_scan_run_id:
            base = db.get(ScanRun, baseline_scan_run_id)
            if not base or base.investigation_id != investigation_id:
                raise ValueError("Baseline ScanRun does not belong to this investigation")
            curr = scans[-1]
            if base.id == curr.id and len(scans) >= 2:
                # If baseline is the latest, compare with previous
                idx = next((i for i, s in enumerate(scans) if s.id == base.id), -1)
                if idx > 0:
                    curr = base
                    base = scans[idx - 1]
            return base, curr

        # Both omitted: default to previous scan vs latest scan
        return scans[-2], scans[-1]

    def _record_change(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        asset_id: Optional[uuid.UUID],
        change_type: str,
        category: str,
        field_name: str,
        entity_key: str,
        description: str,
        old_value: Optional[Dict[str, Any]],
        new_value: Optional[Dict[str, Any]],
        evidence_id: Optional[uuid.UUID],
        evidence_hash: Optional[str],
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Helper to create or update an idempotent ChangeRecord."""
        key = f"{change_type}_{field_name}_{entity_key}"
        existing = existing_by_key.get(key)

        if existing:
            existing.description = description
            existing.old_value = old_value
            existing.new_value = new_value
            existing.evidence_id = evidence_id
            existing.evidence_hash = evidence_hash
            existing.detected_at = now_utc
            changes_to_persist.append(existing)
        else:
            rec = ChangeRecord(
                investigation_id=investigation_id,
                previous_scan_id=baseline_id,
                current_scan_id=current_id,
                asset_id=asset_id,
                change_type=change_type,
                category=category,
                field_name=field_name,
                entity_key=entity_key,
                description=description,
                old_value=old_value,
                new_value=new_value,
                evidence_id=evidence_id,
                evidence_hash=evidence_hash,
                detected_at=now_utc,
            )
            db.add(rec)
            existing_by_key[key] = rec
            changes_to_persist.append(rec)

    def _compare_subdomains(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare active subdomain asset discoveries."""
        # Query subdomains active in baseline
        base_subs: Dict[str, Subdomain] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(Subdomain)
                    .join(Asset, Subdomain.asset_id == Asset.id)
                    .where(
                        Asset.investigation_id == investigation_id,
                        or_(
                            Asset.last_scan_run_id == baseline_id,
                            Subdomain.id.in_(
                                select(DNSRecord.subdomain_id).where(DNSRecord.scan_run_id == baseline_id)
                            ),
                            Subdomain.id.in_(
                                select(subdomain_certificates.c.subdomain_id).where(
                                    subdomain_certificates.c.scan_run_id == baseline_id
                                )
                            ),
                        ),
                    )
                )
                .scalars()
                .all()
            )
            base_subs = {s.subdomain_name.lower(): s for s in rows}

        # Query subdomains active in current
        curr_rows = (
            db.execute(
                select(Subdomain)
                .join(Asset, Subdomain.asset_id == Asset.id)
                .where(
                    Asset.investigation_id == investigation_id,
                    or_(
                        Asset.last_scan_run_id == current_id,
                        Subdomain.id.in_(
                            select(DNSRecord.subdomain_id).where(DNSRecord.scan_run_id == current_id)
                        ),
                        Subdomain.id.in_(
                            select(subdomain_certificates.c.subdomain_id).where(
                                subdomain_certificates.c.scan_run_id == current_id
                            )
                        ),
                    ),
                )
            )
            .scalars()
            .all()
        )
        curr_subs = {s.subdomain_name.lower(): s for s in curr_rows}

        # ADDED
        for name, sub in curr_subs.items():
            if name not in base_subs:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=sub.asset_id,
                    change_type="ADDED",
                    category="subdomain",
                    field_name="subdomain",
                    entity_key=f"subdomain:{name}",
                    description=f"New subdomain '{name}' discovered",
                    old_value=None,
                    new_value={"subdomain_name": name, "is_resolving": sub.is_resolving, "discovery_source": sub.discovery_source},
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for name, sub in base_subs.items():
            if name not in curr_subs:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=sub.asset_id,
                    change_type="REMOVED",
                    category="subdomain",
                    field_name="subdomain",
                    entity_key=f"subdomain:{name}",
                    description=f"Subdomain '{name}' is no longer active or observed in current scan",
                    old_value={"subdomain_name": name, "is_resolving": sub.is_resolving, "discovery_source": sub.discovery_source},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED
        for name, curr_sub in curr_subs.items():
            if name in base_subs:
                base_sub = base_subs[name]
                if base_sub.is_resolving != curr_sub.is_resolving:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_sub.asset_id,
                        change_type="MODIFIED",
                        category="subdomain",
                        field_name="is_resolving",
                        entity_key=f"subdomain:{name}",
                        description=f"Subdomain '{name}' resolution status changed from {base_sub.is_resolving} to {curr_sub.is_resolving}",
                        old_value={"is_resolving": base_sub.is_resolving},
                        new_value={"is_resolving": curr_sub.is_resolving},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_dns_records(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare DNS records (A, AAAA, CNAME, MX, TXT, NS)."""
        base_records = []
        if baseline_id:
            base_records = (
                db.execute(
                    select(DNSRecord)
                    .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
                    .join(Asset, Subdomain.asset_id == Asset.id)
                    .where(Asset.investigation_id == investigation_id, DNSRecord.scan_run_id == baseline_id)
                )
                .scalars()
                .all()
            )

        curr_records = (
            db.execute(
                select(DNSRecord)
                .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
                .join(Asset, Subdomain.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id, DNSRecord.scan_run_id == current_id)
            )
            .scalars()
            .all()
        )

        base_grouped: Dict[Tuple[str, str], Set[str]] = {}
        base_asset_map: Dict[Tuple[str, str], uuid.UUID] = {}
        for r in base_records:
            sub = r.subdomain.subdomain_name.lower() if r.subdomain else "unknown"
            key = (sub, r.record_type.upper())
            base_grouped.setdefault(key, set()).add(r.value)
            if r.subdomain:
                base_asset_map[key] = r.subdomain.asset_id

        curr_grouped: Dict[Tuple[str, str], Set[str]] = {}
        curr_asset_map: Dict[Tuple[str, str], uuid.UUID] = {}
        for r in curr_records:
            sub = r.subdomain.subdomain_name.lower() if r.subdomain else "unknown"
            key = (sub, r.record_type.upper())
            curr_grouped.setdefault(key, set()).add(r.value)
            if r.subdomain:
                curr_asset_map[key] = r.subdomain.asset_id

        all_keys = set(base_grouped.keys()).union(set(curr_grouped.keys()))
        for sub, rtype in all_keys:
            base_vals = base_grouped.get((sub, rtype), set())
            curr_vals = curr_grouped.get((sub, rtype), set())
            asset_id = curr_asset_map.get((sub, rtype)) or base_asset_map.get((sub, rtype))

            if not base_vals and curr_vals:
                # ADDED
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=asset_id,
                    change_type="ADDED",
                    category="dns_record",
                    field_name="dns_record",
                    entity_key=f"dns:{sub}:{rtype}",
                    description=f"New DNS {rtype} record(s) for {sub}: {sorted(list(curr_vals))}",
                    old_value=None,
                    new_value={"subdomain": sub, "record_type": rtype, "values": sorted(list(curr_vals))},
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )
            elif base_vals and not curr_vals:
                # REMOVED
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=asset_id,
                    change_type="REMOVED",
                    category="dns_record",
                    field_name="dns_record",
                    entity_key=f"dns:{sub}:{rtype}",
                    description=f"DNS {rtype} record(s) for {sub} removed: {sorted(list(base_vals))}",
                    old_value={"subdomain": sub, "record_type": rtype, "values": sorted(list(base_vals))},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )
            elif base_vals != curr_vals:
                # MODIFIED
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=asset_id,
                    change_type="MODIFIED",
                    category="dns_record",
                    field_name="dns_record",
                    entity_key=f"dns:{sub}:{rtype}",
                    description=f"DNS {rtype} records for {sub} modified from {sorted(list(base_vals))} to {sorted(list(curr_vals))}",
                    old_value={"subdomain": sub, "record_type": rtype, "values": sorted(list(base_vals))},
                    new_value={"subdomain": sub, "record_type": rtype, "values": sorted(list(curr_vals))},
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

    def _compare_ip_observations(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare observed IP addresses and ASN routing."""
        base_obs: Dict[str, IPObservation] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(IPObservation)
                    .join(IPAddress, IPObservation.ip_address_id == IPAddress.id)
                    .join(Asset, IPAddress.asset_id == Asset.id)
                    .where(Asset.investigation_id == investigation_id, IPObservation.scan_run_id == baseline_id)
                )
                .scalars()
                .all()
            )
            base_obs = {o.ip_address.ip_address: o for o in rows if o.ip_address}

        curr_rows = (
            db.execute(
                select(IPObservation)
                .join(IPAddress, IPObservation.ip_address_id == IPAddress.id)
                .join(Asset, IPAddress.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id, IPObservation.scan_run_id == current_id)
            )
            .scalars()
            .all()
        )
        curr_obs = {o.ip_address.ip_address: o for o in curr_rows if o.ip_address}

        # ADDED
        for ip, obs in curr_obs.items():
            if ip not in base_obs:
                asn_num = obs.asn.asn_number if obs.asn else None
                asn_name = obs.asn.name if obs.asn else None
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=obs.ip_address.asset_id if obs.ip_address else None,
                    change_type="ADDED",
                    category="ip_observation",
                    field_name="ip_observation",
                    entity_key=f"ip:{ip}",
                    description=f"New IP address observation '{ip}' (ASN: AS{asn_num or 'Unknown'} {asn_name or ''})".strip(),
                    old_value=None,
                    new_value={"ip_address": ip, "asn_number": asn_num, "asn_name": asn_name},
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for ip, obs in base_obs.items():
            if ip not in curr_obs:
                asn_num = obs.asn.asn_number if obs.asn else None
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=obs.ip_address.asset_id if obs.ip_address else None,
                    change_type="REMOVED",
                    category="ip_observation",
                    field_name="ip_observation",
                    entity_key=f"ip:{ip}",
                    description=f"IP address '{ip}' is no longer observed in current scan",
                    old_value={"ip_address": ip, "asn_number": asn_num},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (ASN routing changes)
        for ip, curr_o in curr_obs.items():
            if ip in base_obs:
                base_o = base_obs[ip]
                base_asn = base_o.asn.asn_number if base_o.asn else None
                curr_asn = curr_o.asn.asn_number if curr_o.asn else None
                if base_asn != curr_asn:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_o.ip_address.asset_id if curr_o.ip_address else None,
                        change_type="MODIFIED",
                        category="ip_observation",
                        field_name="asn_routing",
                        entity_key=f"ip:{ip}",
                        description=f"IP '{ip}' ASN routing changed from AS{base_asn or 'None'} to AS{curr_asn or 'None'}",
                        old_value={"ip_address": ip, "asn_number": base_asn, "asn_name": base_o.asn.name if base_o.asn else None},
                        new_value={"ip_address": ip, "asn_number": curr_asn, "asn_name": curr_o.asn.name if curr_o.asn else None},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_service_exposures(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare open ports, HTTP services, TLS versions, and security headers."""
        base_svcs: Dict[str, ServiceExposure] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(ServiceExposure)
                    .join(Asset, ServiceExposure.asset_id == Asset.id)
                    .where(Asset.investigation_id == investigation_id, ServiceExposure.scan_run_id == baseline_id)
                )
                .scalars()
                .all()
            )
            base_svcs = {f"{s.asset.value if s.asset else ''}:{s.protocol}:{s.port}": s for s in rows}

        curr_rows = (
            db.execute(
                select(ServiceExposure)
                .join(Asset, ServiceExposure.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id, ServiceExposure.scan_run_id == current_id)
            )
            .scalars()
            .all()
        )
        curr_svcs = {f"{s.asset.value if s.asset else ''}:{s.protocol}:{s.port}": s for s in curr_rows}

        # ADDED
        for key, svc in curr_svcs.items():
            if key not in base_svcs:
                asset_val = svc.asset.value if svc.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=svc.asset_id,
                    change_type="ADDED",
                    category="service_exposure",
                    field_name="service_exposure",
                    entity_key=f"service:{key}",
                    description=f"New service exposure on {asset_val}:{svc.port}/{svc.protocol} ({svc.service_name})",
                    old_value=None,
                    new_value={
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "service_name": svc.service_name,
                        "http_status": svc.http_status,
                        "tls_version": svc.tls_version,
                        "page_title": svc.page_title,
                    },
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for key, svc in base_svcs.items():
            if key not in curr_svcs:
                asset_val = svc.asset.value if svc.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=svc.asset_id,
                    change_type="REMOVED",
                    category="service_exposure",
                    field_name="service_exposure",
                    entity_key=f"service:{key}",
                    description=f"Service on {asset_val}:{svc.port}/{svc.protocol} is no longer exposed or reachable",
                    old_value={
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "service_name": svc.service_name,
                        "http_status": svc.http_status,
                    },
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (Status code, TLS version, Page title, Security headers)
        for key, curr_s in curr_svcs.items():
            if key in base_svcs:
                base_s = base_svcs[key]
                asset_val = curr_s.asset.value if curr_s.asset else ""
                modified_props = {}

                if base_s.http_status != curr_s.http_status:
                    modified_props["http_status"] = {"old": base_s.http_status, "new": curr_s.http_status}
                if base_s.tls_version != curr_s.tls_version:
                    modified_props["tls_version"] = {"old": base_s.tls_version, "new": curr_s.tls_version}
                if base_s.page_title != curr_s.page_title:
                    modified_props["page_title"] = {"old": base_s.page_title, "new": curr_s.page_title}
                if base_s.service_name != curr_s.service_name:
                    modified_props["service_name"] = {"old": base_s.service_name, "new": curr_s.service_name}

                # Security headers diffing
                base_hdrs = base_s.security_headers or {}
                curr_hdrs = curr_s.security_headers or {}
                hdr_changes = {}
                all_hdr_keys = set(base_hdrs.keys()).union(set(curr_hdrs.keys()))
                for hk in all_hdr_keys:
                    b_p = base_hdrs.get(hk, {}).get("present") if isinstance(base_hdrs.get(hk), dict) else None
                    c_p = curr_hdrs.get(hk, {}).get("present") if isinstance(curr_hdrs.get(hk), dict) else None
                    if b_p != c_p:
                        hdr_changes[hk] = {"old_present": b_p, "new_present": c_p}

                if hdr_changes:
                    modified_props["security_headers"] = hdr_changes

                if modified_props:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_s.asset_id,
                        change_type="MODIFIED",
                        category="service_exposure",
                        field_name="service_properties",
                        entity_key=f"service:{key}",
                        description=f"Service properties modified on {asset_val}:{curr_s.port} ({', '.join(modified_props.keys())})",
                        old_value={k: v["old"] if "old" in v else v for k, v in modified_props.items()},
                        new_value={k: v["new"] if "new" in v else v for k, v in modified_props.items()},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_technologies(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare detected technologies, frameworks, and versions."""
        base_techs: Dict[str, Technology] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(Technology)
                    .join(Asset, Technology.asset_id == Asset.id)
                    .where(Asset.investigation_id == investigation_id, Technology.scan_run_id == baseline_id)
                )
                .scalars()
                .all()
            )
            base_techs = {f"{t.asset.value if t.asset else ''}:{t.name.lower()}": t for t in rows}

        curr_rows = (
            db.execute(
                select(Technology)
                .join(Asset, Technology.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id, Technology.scan_run_id == current_id)
            )
            .scalars()
            .all()
        )
        curr_techs = {f"{t.asset.value if t.asset else ''}:{t.name.lower()}": t for t in curr_rows}

        # ADDED
        for key, tech in curr_techs.items():
            if key not in base_techs:
                asset_val = tech.asset.value if tech.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=tech.asset_id,
                    change_type="ADDED",
                    category="technology",
                    field_name="technology",
                    entity_key=f"technology:{key}",
                    description=f"New technology '{tech.name} {tech.version or ''}' detected on {asset_val}".strip(),
                    old_value=None,
                    new_value={
                        "name": tech.name,
                        "version": tech.version,
                        "cpe": tech.cpe,
                        "category": tech.category,
                        "confidence": tech.confidence,
                    },
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for key, tech in base_techs.items():
            if key not in curr_techs:
                asset_val = tech.asset.value if tech.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=tech.asset_id,
                    change_type="REMOVED",
                    category="technology",
                    field_name="technology",
                    entity_key=f"technology:{key}",
                    description=f"Technology '{tech.name}' no longer detected on {asset_val}",
                    old_value={"name": tech.name, "version": tech.version, "cpe": tech.cpe},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (version upgrade / downgrade / CPE modification)
        for key, curr_t in curr_techs.items():
            if key in base_techs:
                base_t = base_techs[key]
                asset_val = curr_t.asset.value if curr_t.asset else ""
                if base_t.version != curr_t.version or base_t.cpe != curr_t.cpe:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_t.asset_id,
                        change_type="MODIFIED",
                        category="technology",
                        field_name="version",
                        entity_key=f"technology:{key}",
                        description=f"Technology '{curr_t.name}' on {asset_val} version changed from '{base_t.version or 'unknown'}' to '{curr_t.version or 'unknown'}'",
                        old_value={"version": base_t.version, "cpe": base_t.cpe, "confidence": base_t.confidence},
                        new_value={"version": curr_t.version, "cpe": curr_t.cpe, "confidence": curr_t.confidence},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_vulnerabilities(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare vulnerability correlations between scans."""
        base_vulns: Dict[str, Tuple[TechnologyVulnerability, Technology, Vulnerability]] = {}
        if baseline_id:
            rows = db.execute(
                select(TechnologyVulnerability, Technology, Vulnerability)
                .join(Technology, TechnologyVulnerability.technology_id == Technology.id)
                .join(Vulnerability, TechnologyVulnerability.vulnerability_id == Vulnerability.id)
                .join(Asset, Technology.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id, Technology.scan_run_id == baseline_id)
            ).all()
            for tv, t, v in rows:
                key = f"{t.asset.value if t.asset else ''}:{t.name.lower()}:{v.cve_id}"
                base_vulns[key] = (tv, t, v)

        curr_rows = db.execute(
            select(TechnologyVulnerability, Technology, Vulnerability)
            .join(Technology, TechnologyVulnerability.technology_id == Technology.id)
            .join(Vulnerability, TechnologyVulnerability.vulnerability_id == Vulnerability.id)
            .join(Asset, Technology.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id, Technology.scan_run_id == current_id)
        ).all()
        curr_vulns: Dict[str, Tuple[TechnologyVulnerability, Technology, Vulnerability]] = {}
        for tv, t, v in curr_rows:
            key = f"{t.asset.value if t.asset else ''}:{t.name.lower()}:{v.cve_id}"
            curr_vulns[key] = (tv, t, v)

        # ADDED
        for key, (tv, t, v) in curr_vulns.items():
            if key not in base_vulns:
                asset_val = t.asset.value if t.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=t.asset_id,
                    change_type="ADDED",
                    category="vulnerability",
                    field_name="vulnerability",
                    entity_key=f"vuln:{key}",
                    description=f"New vulnerability correlated: {v.cve_id} ({v.severity}) affecting {t.name} on {asset_val}",
                    old_value=None,
                    new_value={
                        "cve_id": v.cve_id,
                        "technology": t.name,
                        "version": t.version,
                        "severity": v.severity,
                        "cvss_score": v.cvss_v3_score,
                    },
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED (No longer observed in current scan)
        for key, (tv, t, v) in base_vulns.items():
            if key not in curr_vulns:
                asset_val = t.asset.value if t.asset else ""
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=t.asset_id,
                    change_type="REMOVED",
                    category="vulnerability",
                    field_name="vulnerability",
                    entity_key=f"vuln:{key}",
                    description=f"Vulnerability {v.cve_id} on {asset_val} no longer observed in current scan",
                    old_value={"cve_id": v.cve_id, "technology": t.name, "severity": v.severity, "match_confidence": tv.match_confidence},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (Match confidence or verification status changes)
        for key, (curr_tv, curr_t, curr_v) in curr_vulns.items():
            if key in base_vulns:
                base_tv, base_t, base_v = base_vulns[key]
                if base_tv.match_confidence != curr_tv.match_confidence or base_tv.verification_status != curr_tv.verification_status:
                    asset_val = curr_t.asset.value if curr_t.asset else ""
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_t.asset_id,
                        change_type="MODIFIED",
                        category="vulnerability",
                        field_name="vulnerability_confidence",
                        entity_key=f"vuln:{key}",
                        description=f"Vulnerability {curr_v.cve_id} on {asset_val} confidence modified from {base_tv.match_confidence} to {curr_tv.match_confidence}",
                        old_value={"match_confidence": base_tv.match_confidence, "verification_status": base_tv.verification_status},
                        new_value={"match_confidence": curr_tv.match_confidence, "verification_status": curr_tv.verification_status},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_certificates(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare observed TLS certificates and expiration statuses."""
        base_certs: Dict[str, Tuple[Subdomain, Certificate]] = {}
        if baseline_id:
            rows = db.execute(
                select(Subdomain, Certificate)
                .join(subdomain_certificates, Subdomain.id == subdomain_certificates.c.subdomain_id)
                .join(Certificate, subdomain_certificates.c.certificate_id == Certificate.id)
                .join(Asset, Subdomain.asset_id == Asset.id)
                .where(
                    Asset.investigation_id == investigation_id,
                    subdomain_certificates.c.scan_run_id == baseline_id,
                )
            ).all()
            for sub, cert in rows:
                key = f"{sub.subdomain_name.lower()}:{cert.fingerprint_sha256}"
                base_certs[key] = (sub, cert)

        curr_rows = db.execute(
            select(Subdomain, Certificate)
            .join(subdomain_certificates, Subdomain.id == subdomain_certificates.c.subdomain_id)
            .join(Certificate, subdomain_certificates.c.certificate_id == Certificate.id)
            .join(Asset, Subdomain.asset_id == Asset.id)
            .where(
                Asset.investigation_id == investigation_id,
                subdomain_certificates.c.scan_run_id == current_id,
            )
        ).all()
        curr_certs: Dict[str, Tuple[Subdomain, Certificate]] = {}
        for sub, cert in curr_rows:
            key = f"{sub.subdomain_name.lower()}:{cert.fingerprint_sha256}"
            curr_certs[key] = (sub, cert)

        # ADDED (New certificate observed)
        for key, (sub, cert) in curr_certs.items():
            if key not in base_certs:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=sub.asset_id,
                    change_type="ADDED",
                    category="certificate",
                    field_name="certificate",
                    entity_key=f"cert:{key}",
                    description=f"New TLS certificate observed for {sub.subdomain_name} (CN: {cert.subject_cn})",
                    old_value=None,
                    new_value={"subject_cn": cert.subject_cn, "issuer": cert.issuer, "is_expired": cert.is_expired},
                    evidence_id=None,
                    evidence_hash=cert.fingerprint_sha256,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED (Certificate no longer observed on this host)
        for key, (sub, cert) in base_certs.items():
            if key not in curr_certs:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=sub.asset_id,
                    change_type="REMOVED",
                    category="certificate",
                    field_name="certificate",
                    entity_key=f"cert:{key}",
                    description=f"TLS certificate (CN: {cert.subject_cn}) no longer observed for {sub.subdomain_name}",
                    old_value={"subject_cn": cert.subject_cn, "fingerprint": cert.fingerprint_sha256, "is_expired": cert.is_expired},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=cert.fingerprint_sha256,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (Tracked metadata change on the same certificate identity)
        for key, (curr_sub, curr_cert) in curr_certs.items():
            if key in base_certs:
                base_sub, base_cert = base_certs[key]
                if base_cert.is_expired != curr_cert.is_expired:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_sub.asset_id,
                        change_type="MODIFIED",
                        category="certificate",
                        field_name="certificate_expiration",
                        entity_key=f"cert:{key}",
                        description=f"TLS certificate (CN: {curr_cert.subject_cn}) expiration status changed from {base_cert.is_expired} to {curr_cert.is_expired}",
                        old_value={"is_expired": base_cert.is_expired, "valid_to": base_cert.valid_to.isoformat() if base_cert.valid_to else None},
                        new_value={"is_expired": curr_cert.is_expired, "valid_to": curr_cert.valid_to.isoformat() if curr_cert.valid_to else None},
                        evidence_id=None,
                        evidence_hash=curr_cert.fingerprint_sha256,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    def _compare_relationships(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare graph topology relationships between scans."""
        base_rels: Dict[str, AssetRelationship] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(AssetRelationship).where(
                        AssetRelationship.investigation_id == investigation_id,
                        AssetRelationship.scan_run_id == baseline_id,
                    )
                )
                .scalars()
                .all()
            )
            base_rels = {f"{r.source_asset_id}:{r.relationship_type}:{r.target_asset_id}": r for r in rows}

        curr_rows = (
            db.execute(
                select(AssetRelationship).where(
                    AssetRelationship.investigation_id == investigation_id,
                    AssetRelationship.scan_run_id == current_id,
                )
            )
            .scalars()
            .all()
        )
        curr_rels = {f"{r.source_asset_id}:{r.relationship_type}:{r.target_asset_id}": r for r in curr_rows}

        # ADDED
        for key, rel in curr_rels.items():
            if key not in base_rels:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=rel.source_asset_id,
                    change_type="ADDED",
                    category="asset_relationship",
                    field_name="relationship",
                    entity_key=f"rel:{key}",
                    description=f"New attack surface relationship established: {rel.relationship_type}",
                    old_value=None,
                    new_value={"relationship_type": rel.relationship_type, "confidence": rel.confidence},
                    evidence_id=rel.evidence_id,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for key, rel in base_rels.items():
            if key not in curr_rels:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=rel.source_asset_id,
                    change_type="REMOVED",
                    category="asset_relationship",
                    field_name="relationship",
                    entity_key=f"rel:{key}",
                    description=f"Attack surface relationship removed: {rel.relationship_type}",
                    old_value={"relationship_type": rel.relationship_type, "confidence": rel.confidence},
                    new_value=None,
                    evidence_id=rel.evidence_id,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

    def _compare_findings(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID],
        current_id: uuid.UUID,
        existing_by_key: Dict[str, ChangeRecord],
        changes_to_persist: List[ChangeRecord],
        now_utc: datetime,
    ) -> None:
        """Compare security findings between scans."""
        base_findings: Dict[str, Finding] = {}
        if baseline_id:
            rows = (
                db.execute(
                    select(Finding).where(
                        Finding.investigation_id == investigation_id,
                        Finding.scan_run_id == baseline_id,
                    )
                )
                .scalars()
                .all()
            )
            base_findings = {f"{f.asset_id}_{f.category}_{f.title}": f for f in rows}

        curr_rows = (
            db.execute(
                select(Finding).where(
                    Finding.investigation_id == investigation_id,
                    Finding.scan_run_id == current_id,
                )
            )
            .scalars()
            .all()
        )
        curr_findings = {f"{f.asset_id}_{f.category}_{f.title}": f for f in curr_rows}

        # ADDED
        for key, finding in curr_findings.items():
            if key not in base_findings:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=finding.asset_id,
                    change_type="ADDED",
                    category="finding",
                    field_name="finding",
                    entity_key=f"finding:{key}",
                    description=f"New finding: {finding.title} (Severity: {finding.severity}, Risk: {finding.context_score}/100)",
                    old_value=None,
                    new_value={
                        "title": finding.title,
                        "severity": finding.severity,
                        "context_score": finding.context_score,
                        "status": finding.status,
                    },
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # REMOVED
        for key, finding in base_findings.items():
            if key not in curr_findings:
                self._record_change(
                    db=db,
                    investigation_id=investigation_id,
                    baseline_id=baseline_id,
                    current_id=current_id,
                    asset_id=finding.asset_id,
                    change_type="REMOVED",
                    category="finding",
                    field_name="finding",
                    entity_key=f"finding:{key}",
                    description=f"Security finding no longer observed in current scan: {finding.title}",
                    old_value={"title": finding.title, "severity": finding.severity, "context_score": finding.context_score},
                    new_value=None,
                    evidence_id=None,
                    evidence_hash=None,
                    existing_by_key=existing_by_key,
                    changes_to_persist=changes_to_persist,
                    now_utc=now_utc,
                )

        # MODIFIED (Status / Risk Score changes)
        for key, curr_f in curr_findings.items():
            if key in base_findings:
                base_f = base_findings[key]
                if base_f.status != curr_f.status or base_f.context_score != curr_f.context_score or base_f.severity != curr_f.severity:
                    self._record_change(
                        db=db,
                        investigation_id=investigation_id,
                        baseline_id=baseline_id,
                        current_id=current_id,
                        asset_id=curr_f.asset_id,
                        change_type="MODIFIED",
                        category="finding",
                        field_name="finding_status",
                        entity_key=f"finding:{key}",
                        description=f"Finding '{curr_f.title}' updated: Status {base_f.status} -> {curr_f.status}, Risk {base_f.context_score} -> {curr_f.context_score}",
                        old_value={"status": base_f.status, "severity": base_f.severity, "context_score": base_f.context_score},
                        new_value={"status": curr_f.status, "severity": curr_f.severity, "context_score": curr_f.context_score},
                        evidence_id=None,
                        evidence_hash=None,
                        existing_by_key=existing_by_key,
                        changes_to_persist=changes_to_persist,
                        now_utc=now_utc,
                    )

    @staticmethod
    def _serialize_change(c: ChangeRecord) -> ChangeRecordResponse:
        """Convert ChangeRecord model to standardized Pydantic response."""
        asset_val = c.asset.value if c.asset else None
        return ChangeRecordResponse(
            id=c.id,
            investigation_id=c.investigation_id,
            baseline_scan_run_id=c.previous_scan_id,
            current_scan_run_id=c.current_scan_id,
            asset_id=c.asset_id,
            asset_value=asset_val,
            change_type=c.change_type,
            field_name=c.field_name,
            category=c.category or c.field_name,
            entity_key=c.entity_key,
            description=c.description,
            old_value=c.old_value,
            new_value=c.new_value,
            evidence_id=c.evidence_id,
            evidence_hash=c.evidence_hash,
            detected_at=c.detected_at,
        )
