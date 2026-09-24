"""Investigation management and Certificate Transparency discovery API endpoints."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_active_user
from backend.app.core.logging import logger
from backend.app.database.connection import get_db
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, ServiceExposure, IPAddress, ASN, IPObservation
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.evidence import Evidence
from backend.app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationResponse,
    CTDiscoveryResponse,
    CertificateSummaryResponse,
    AssetSummaryResponse,
    DNSRecordSummaryResponse,
    ServiceExposureSummaryResponse,
    CandidateResolutionDetail,
    DNSReachabilityResponse,
    ASNSummaryResponse,
    RDAPSummaryResponse,
    IPAddressSummaryResponse,
    IPObservationSummaryResponse,
    IPEnrichmentDetail,
    IPEnrichmentResponse,
)
from backend.app.services.ct_service import CTService, CTProviderError
from backend.app.services.dns_service import DNSService
from backend.app.services.reachability_service import ReachabilityService
from backend.app.services.ip_service import IPService
from backend.app.services.asn_service import ASNService
from backend.app.services.rdap_service import RDAPService


def get_ct_service() -> CTService:
    """Dependency provider returning CTService instance."""
    return CTService()


def get_dns_service() -> DNSService:
    """Dependency provider returning DNSService instance."""
    return DNSService()


def get_reachability_service() -> ReachabilityService:
    """Dependency provider returning ReachabilityService instance."""
    return ReachabilityService()


def get_ip_service() -> IPService:
    """Dependency provider returning IPService instance."""
    return IPService()


def get_asn_service() -> ASNService:
    """Dependency provider returning ASNService instance."""
    return ASNService()


def get_rdap_service() -> RDAPService:
    """Dependency provider returning RDAPService instance."""
    return RDAPService()



router = APIRouter(prefix="/investigations", tags=["Investigations & OSINT Discovery"])


def _check_investigation_access(investigation: Investigation, user: User) -> None:
    """Enforce access control: only investigation owner or admin can view/modify."""
    if user.role != "admin" and investigation.created_by_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden. You are not authorized to access this investigation.",
        )


def _generate_reference_code(db: Session) -> str:
    """Generate a unique human-readable investigation reference code."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    count = db.execute(select(func.count(Investigation.id))).scalar() or 0
    random_suffix = uuid.uuid4().hex[:4].upper()
    return f"INV-{date_str}-{count + 1:03d}-{random_suffix}"


@router.post(
    "",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Investigation Assessment",
    description="Validates target domain, registers target scope, and creates an investigation instance.",
)
def create_investigation(
    payload: InvestigationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> InvestigationResponse:
    """Create a new authorized investigation for a validated target domain."""
    normalized_domain = payload.target_domain

    # Find or create Target entity
    target = db.execute(
        select(Target).where(Target.primary_domain == normalized_domain)
    ).scalar_one_or_none()

    if not target:
        target = Target(
            name=payload.organization or payload.name,
            primary_domain=normalized_domain,
            organization=payload.organization,
            description=payload.description,
            is_authorized=True,
        )
        db.add(target)
        db.flush()

    # Generate unique reference code
    ref_code = _generate_reference_code(db)

    investigation = Investigation(
        reference_code=ref_code,
        target_id=target.id,
        title=payload.name,
        status="pending",
        scan_options=payload.scan_options,
        created_by_id=current_user.id,
    )
    db.add(investigation)
    db.flush()

    # Ensure root domain asset exists
    root_asset = db.execute(
        select(Asset).where(
            Asset.target_id == target.id,
            Asset.investigation_id == investigation.id,
            Asset.value == normalized_domain,
        )
    ).scalar_one_or_none()

    if not root_asset:
        root_asset = Asset(
            target_id=target.id,
            investigation_id=investigation.id,
            asset_type="domain",
            value=normalized_domain,
            is_active=True,
            source="target_scope",
            confidence=1.0,
            tags=["primary_target", "root_domain"],
        )
        db.add(root_asset)
        db.flush()

        domain_rec = Domain(
            asset_id=root_asset.id,
            domain_name=normalized_domain,
        )
        db.add(domain_rec)

    db.commit()
    db.refresh(investigation)

    logger.info(
        f"Investigation created: code='{investigation.reference_code}', "
        f"target='{normalized_domain}', creator='{current_user.username}'"
    )

    return InvestigationResponse(
        id=investigation.id,
        reference_code=investigation.reference_code,
        target_id=target.id,
        target_domain=target.primary_domain,
        title=investigation.title,
        status=investigation.status,
        scan_options=investigation.scan_options,
        created_by_id=investigation.created_by_id,
        started_at=investigation.started_at,
        completed_at=investigation.completed_at,
        created_at=investigation.created_at,
    )


@router.get(
    "",
    response_model=List[InvestigationResponse],
    summary="List Investigations",
    description="Returns assessments created by the authenticated analyst, or all assessments for admins.",
)
def list_investigations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[InvestigationResponse]:
    """List accessible investigations."""
    query = select(Investigation).order_by(Investigation.created_at.desc())
    if current_user.role != "admin":
        query = query.where(Investigation.created_by_id == current_user.id)

    investigations = db.execute(query).scalars().all()

    return [
        InvestigationResponse(
            id=inv.id,
            reference_code=inv.reference_code,
            target_id=inv.target_id,
            target_domain=inv.target.primary_domain if inv.target else "",
            title=inv.title,
            status=inv.status,
            scan_options=inv.scan_options,
            created_by_id=inv.created_by_id,
            started_at=inv.started_at,
            completed_at=inv.completed_at,
            created_at=inv.created_at,
        )
        for inv in investigations
    ]


@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Get Investigation Details",
)
def get_investigation(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> InvestigationResponse:
    """Retrieve details of a single investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    return InvestigationResponse(
        id=investigation.id,
        reference_code=investigation.reference_code,
        target_id=investigation.target_id,
        target_domain=investigation.target.primary_domain if investigation.target else "",
        title=investigation.title,
        status=investigation.status,
        scan_options=investigation.scan_options,
        created_by_id=investigation.created_by_id,
        started_at=investigation.started_at,
        completed_at=investigation.completed_at,
        created_at=investigation.created_at,
    )


@router.post(
    "/{investigation_id}/discover/ct",
    response_model=CTDiscoveryResponse,
    summary="Run Certificate Transparency Discovery",
    description=(
        "Queries public Certificate Transparency logs for the target domain, "
        "extracts and normalizes hostname candidates, stores observed certificates, "
        "and updates the investigation scan history."
    ),
)
def run_ct_discovery(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    ct_service: CTService = Depends(get_ct_service),
) -> CTDiscoveryResponse:
    """Trigger passive Certificate Transparency reconnaissance for investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    target = investigation.target
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target associated with investigation not found",
        )

    target_domain = target.primary_domain
    now_utc = datetime.now(timezone.utc)

    # Determine next ScanRun number
    scan_run_count = db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.investigation_id == investigation.id)
    ).scalar() or 0

    scan_run = ScanRun(
        investigation_id=investigation.id,
        run_number=scan_run_count + 1,
        status="running",
        started_at=now_utc,
    )
    db.add(scan_run)
    db.flush()

    try:
        discovery_result = ct_service.discover(target_domain)
    except CTProviderError as err:
        scan_run.status = "failed"
        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.summary = {"error": str(err)}
        db.commit()
        logger.error(f"CT discovery failed for investigation '{investigation.reference_code}': {err}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Certificate Transparency provider error: {str(err)}",
        )

    # Ensure Domain record for root target exists
    root_domain_rec = db.execute(
        select(Domain).where(Domain.domain_name == target_domain)
    ).scalar_one_or_none()

    if not root_domain_rec:
        # Check root asset
        root_asset = db.execute(
            select(Asset).where(
                Asset.target_id == target.id,
                Asset.investigation_id == investigation.id,
                Asset.value == target_domain,
            )
        ).scalar_one_or_none()
        if not root_asset:
            root_asset = Asset(
                target_id=target.id,
                investigation_id=investigation.id,
                asset_type="domain",
                value=target_domain,
                is_active=True,
                source="crt.sh",
                last_scan_run_id=scan_run.id,
            )
            db.add(root_asset)
            db.flush()
        root_domain_rec = Domain(asset_id=root_asset.id, domain_name=target_domain)
        db.add(root_domain_rec)
        db.flush()

    # Map for tracking Subdomain entities
    subdomain_entities_by_name: dict[str, Subdomain] = {}

    # Store discovered hostname candidates as Asset + Subdomain
    for hostname in discovery_result.hostnames:
        is_root = (hostname == target_domain)
        asset_type = "domain" if is_root else "subdomain"

        # Check existing asset for this investigation
        asset = db.execute(
            select(Asset).where(
                Asset.investigation_id == investigation.id,
                Asset.value == hostname,
            )
        ).scalar_one_or_none()

        if not asset:
            asset = Asset(
                target_id=target.id,
                investigation_id=investigation.id,
                asset_type=asset_type,
                value=hostname,
                # CT discovery does NOT prove host is active: candidate only
                is_active=False,
                confidence=0.85,
                source="crt.sh",
                tags=["ct_candidate", "passive_discovery"],
                last_scan_run_id=scan_run.id,
            )
            db.add(asset)
            db.flush()
        else:
            asset.last_scan_run_id = scan_run.id
            asset.last_seen_at = now_utc

        if not is_root:
            subdomain = db.execute(
                select(Subdomain).where(Subdomain.asset_id == asset.id)
            ).scalar_one_or_none()
            if not subdomain:
                subdomain = Subdomain(
                    asset_id=asset.id,
                    domain_id=root_domain_rec.id,
                    subdomain_name=hostname,
                    is_resolving=False,  # Unresolved until Stage 3B DNS probe
                    discovery_source="crt.sh",
                )
                db.add(subdomain)
                db.flush()
            subdomain_entities_by_name[hostname] = subdomain

    # Store Certificates and link to subdomains
    certificate_summaries: List[CertificateSummaryResponse] = []

    for cert_rec in discovery_result.certificates:
        cert_db = db.execute(
            select(Certificate).where(Certificate.fingerprint_sha256 == cert_rec.fingerprint_sha256)
        ).scalar_one_or_none()

        if not cert_db:
            cert_db = Certificate(
                fingerprint_sha256=cert_rec.fingerprint_sha256,
                serial_number=cert_rec.serial_number,
                subject_cn=cert_rec.subject_cn,
                issuer=cert_rec.issuer,
                san_list=cert_rec.san_list,
                valid_from=cert_rec.valid_from,
                valid_to=cert_rec.valid_to,
                is_expired=cert_rec.is_expired,
                ct_log_id=cert_rec.ct_log_id,
                raw_data=cert_rec.raw_data,
            )
            db.add(cert_db)
            db.flush()

        # Link relevant subdomains to this certificate in subdomain_certificates association table
        for san_name in cert_rec.san_list:
            sub_ent = subdomain_entities_by_name.get(san_name)
            if sub_ent:
                # Check if association already exists
                existing_assoc = db.execute(
                    select(subdomain_certificates).where(
                        subdomain_certificates.c.subdomain_id == sub_ent.id,
                        subdomain_certificates.c.certificate_id == cert_db.id,
                    )
                ).first()
                if not existing_assoc:
                    db.execute(
                        subdomain_certificates.insert().values(
                            subdomain_id=sub_ent.id,
                            certificate_id=cert_db.id,
                            scan_run_id=scan_run.id,
                            observed_at=now_utc,
                        )
                    )

        certificate_summaries.append(
            CertificateSummaryResponse(
                fingerprint_sha256=cert_db.fingerprint_sha256,
                subject_cn=cert_db.subject_cn,
                issuer=cert_db.issuer,
                san_list=cert_db.san_list,
                valid_from=cert_db.valid_from,
                valid_to=cert_db.valid_to,
                is_expired=cert_db.is_expired,
                ct_log_id=cert_db.ct_log_id,
            )
        )

    # Complete ScanRun
    scan_run.status = "completed"
    scan_run.completed_at = datetime.now(timezone.utc)
    scan_run.total_discovered_assets = len(discovery_result.hostnames)
    scan_run.summary = {
        "source": "crt.sh",
        "discovered_hostnames_count": len(discovery_result.hostnames),
        "certificates_count": len(discovery_result.certificates),
    }

    # Update Investigation
    investigation.status = "active"
    if not investigation.started_at:
        investigation.started_at = now_utc

    db.commit()

    logger.info(
        f"Stored CT discovery results for '{target_domain}': "
        f"{len(discovery_result.hostnames)} assets, {len(discovery_result.certificates)} certs"
    )

    return CTDiscoveryResponse(
        investigation_id=investigation.id,
        target_domain=target_domain,
        scan_run_id=scan_run.id,
        source="crt.sh",
        hostname_count=len(discovery_result.hostnames),
        certificate_count=len(certificate_summaries),
        hostnames=discovery_result.hostnames,
        certificates=certificate_summaries,
        discovery_timestamp=discovery_result.retrieval_timestamp,
    )


@router.get(
    "/{investigation_id}/assets",
    response_model=List[AssetSummaryResponse],
    summary="List Discovered Assets for Investigation",
)
def list_investigation_assets(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[AssetSummaryResponse]:
    """Retrieve all assets associated with an investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    assets = db.execute(
        select(Asset)
        .where(Asset.investigation_id == investigation_id)
        .order_by(Asset.value.asc())
    ).scalars().all()

    return [AssetSummaryResponse.model_validate(a) for a in assets]


@router.post(
    "/{investigation_id}/resolve",
    response_model=DNSReachabilityResponse,
    summary="Run Active DNS Resolution & Reachability Probing",
    description=(
        "Actively probes CT-discovered candidate subdomains for DNS resolution (A, AAAA, CNAME, MX, NS, TXT) "
        "and basic HTTP/HTTPS reachability, associating observations with a new ScanRun."
    ),
)
def run_dns_and_reachability(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    dns_service: DNSService = Depends(get_dns_service),
    reachability_service: ReachabilityService = Depends(get_reachability_service),
) -> DNSReachabilityResponse:
    """Execute Stage 3B Active DNS Resolution and Reachability Verification."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    target = investigation.target
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target associated with investigation not found",
        )

    target_domain = target.primary_domain
    now_utc = datetime.now(timezone.utc)

    # 1. Start a new ScanRun for this active probe
    scan_run_count = db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.investigation_id == investigation.id)
    ).scalar() or 0

    scan_run = ScanRun(
        investigation_id=investigation.id,
        run_number=scan_run_count + 1,
        status="running",
        started_at=now_utc,
    )
    db.add(scan_run)
    db.flush()

    # 2. Get or create root Domain record
    root_domain_rec = db.execute(
        select(Domain).where(Domain.domain_name == target_domain)
    ).scalar_one_or_none()

    if not root_domain_rec:
        root_asset = db.execute(
            select(Asset).where(
                Asset.target_id == target.id,
                Asset.investigation_id == investigation.id,
                Asset.value == target_domain,
            )
        ).scalar_one_or_none()
        if not root_asset:
            root_asset = Asset(
                target_id=target.id,
                investigation_id=investigation.id,
                asset_type="domain",
                value=target_domain,
                is_active=True,
                source="target_scope",
                last_scan_run_id=scan_run.id,
            )
            db.add(root_asset)
            db.flush()
        root_domain_rec = Domain(asset_id=root_asset.id, domain_name=target_domain)
        db.add(root_domain_rec)
        db.flush()

    # 3. Retrieve all candidate assets for this investigation (subdomains and domains)
    candidate_assets = db.execute(
        select(Asset)
        .where(
            Asset.investigation_id == investigation.id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
        .order_by(Asset.value.asc())
    ).scalars().all()

    results_detail: List[CandidateResolutionDetail] = []
    resolved_count = 0
    not_resolved_count = 0
    reachable_count = 0
    unreachable_count = 0
    total_dns_records_count = 0
    total_services_count = 0

    for asset in candidate_assets:
        hostname = asset.value

        # Ensure Subdomain record exists for attaching DNS records
        subdomain = db.execute(
            select(Subdomain).where(Subdomain.asset_id == asset.id)
        ).scalar_one_or_none()

        if not subdomain:
            subdomain = Subdomain(
                asset_id=asset.id,
                domain_id=root_domain_rec.id,
                subdomain_name=hostname,
                is_resolving=False,
                discovery_source=asset.source or "candidate_discovery",
            )
            db.add(subdomain)
            db.flush()

        # Step A: Perform DNS resolution
        dns_res = dns_service.resolve(hostname)
        candidate_dns_summaries: List[DNSRecordSummaryResponse] = []
        candidate_service_summaries: List[ServiceExposureSummaryResponse] = []

        is_host_reachable = False

        if dns_res.is_resolving:
            resolved_count += 1
            subdomain.is_resolving = True
            subdomain.last_observed_at = now_utc
            asset.is_active = True
            asset.last_scan_run_id = scan_run.id
            asset.last_seen_at = now_utc

            # Persist DNS records
            for rec in dns_res.records:
                dns_rec_db = DNSRecord(
                    subdomain_id=subdomain.id,
                    scan_run_id=scan_run.id,
                    record_type=rec.record_type,
                    value=rec.value,
                    ttl=rec.ttl,
                    resolver=rec.resolver,
                    collected_at=rec.collected_at,
                )
                db.add(dns_rec_db)
                db.flush()
                total_dns_records_count += 1

                candidate_dns_summaries.append(
                    DNSRecordSummaryResponse(
                        id=dns_rec_db.id,
                        subdomain_id=subdomain.id,
                        record_type=dns_rec_db.record_type,
                        value=dns_rec_db.value,
                        ttl=dns_rec_db.ttl,
                        resolver=dns_rec_db.resolver,
                        collected_at=dns_rec_db.collected_at,
                        scan_run_id=scan_run.id,
                    )
                )

            # Extract resolved IPv4 and IPv6 addresses for pre-flight SSRF validation
            resolved_ips = [
                rec.value for rec in dns_res.records if rec.record_type in ("A", "AAAA")
            ]

            # Step B: Perform Reachability Probing for resolving hostnames (SSRF-protected)
            probe_results = reachability_service.probe_hostname(
                hostname, resolved_ips=resolved_ips
            )

            for probe in probe_results:

                if probe.is_reachable:
                    is_host_reachable = True
                    svc_db = ServiceExposure(
                        asset_id=asset.id,
                        scan_run_id=scan_run.id,
                        port=probe.port,
                        protocol=probe.protocol,
                        service_name=probe.service_name,
                        http_status=probe.status_code,
                        page_title=probe.page_title,
                        observed_at=probe.observed_at,
                    )
                    db.add(svc_db)
                    db.flush()
                    total_services_count += 1

                    candidate_service_summaries.append(
                        ServiceExposureSummaryResponse(
                            id=svc_db.id,
                            asset_id=asset.id,
                            port=svc_db.port,
                            protocol=svc_db.protocol,
                            service_name=svc_db.service_name,
                            http_status=svc_db.http_status,
                            page_title=svc_db.page_title,
                            observed_at=svc_db.observed_at,
                            scan_run_id=scan_run.id,
                        )
                    )

            if is_host_reachable:
                reachable_count += 1
            else:
                unreachable_count += 1

        else:
            # Candidate did not resolve - retain candidate without deleting
            not_resolved_count += 1
            subdomain.is_resolving = False
            subdomain.last_observed_at = now_utc
            asset.last_scan_run_id = scan_run.id
            asset.last_seen_at = now_utc
            # Note: We do NOT delete non-resolving candidates.

        results_detail.append(
            CandidateResolutionDetail(
                hostname=hostname,
                is_resolving=dns_res.is_resolving,
                is_reachable=is_host_reachable,
                dns_records_count=len(candidate_dns_summaries),
                services_count=len(candidate_service_summaries),
                dns_records=candidate_dns_summaries,
                service_exposures=candidate_service_summaries,
                error=dns_res.error,
            )
        )

    # 4. Finalize ScanRun
    scan_run.status = "completed"
    scan_run.completed_at = datetime.now(timezone.utc)
    scan_run.total_discovered_assets = resolved_count
    scan_run.summary = {
        "operation": "dns_reachability_probe",
        "candidates_processed": len(candidate_assets),
        "resolved": resolved_count,
        "not_resolved": not_resolved_count,
        "reachable": reachable_count,
        "unreachable": unreachable_count,
        "dns_records_discovered": total_dns_records_count,
        "services_discovered": total_services_count,
    }

    db.commit()

    logger.info(
        f"Completed Stage 3B resolution for '{target_domain}': "
        f"{len(candidate_assets)} processed, {resolved_count} resolved, "
        f"{reachable_count} reachable, {total_dns_records_count} DNS records."
    )

    return DNSReachabilityResponse(
        investigation_id=investigation.id,
        scan_run_id=scan_run.id,
        target_domain=target_domain,
        candidates_processed=len(candidate_assets),
        resolved=resolved_count,
        not_resolved=not_resolved_count,
        reachable=reachable_count,
        unreachable=unreachable_count,
        dns_records_discovered=total_dns_records_count,
        services_discovered=total_services_count,
        results=results_detail,
        completed_at=scan_run.completed_at,
    )


@router.get(
    "/{investigation_id}/dns-records",
    response_model=List[DNSRecordSummaryResponse],
    summary="List Observed DNS Records for Investigation",
    description="Returns all historical and current DNS records collected for subdomains under this investigation.",
)
def list_investigation_dns_records(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[DNSRecordSummaryResponse]:
    """Retrieve DNS records for all subdomains in the investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    records = db.execute(
        select(DNSRecord)
        .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
        .join(Asset, Subdomain.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(DNSRecord.collected_at.desc())
    ).scalars().all()

    return [DNSRecordSummaryResponse.model_validate(r) for r in records]


@router.get(
    "/{investigation_id}/services",
    response_model=List[ServiceExposureSummaryResponse],
    summary="List Discovered Service Exposures for Investigation",
    description="Returns all HTTP/HTTPS network service reachability observations for assets under this investigation.",
)
def list_investigation_services(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[ServiceExposureSummaryResponse]:
    """Retrieve service exposure observations for all assets in the investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    services = db.execute(
        select(ServiceExposure)
        .join(Asset, ServiceExposure.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(ServiceExposure.observed_at.desc())
    ).scalars().all()

    return [ServiceExposureSummaryResponse.model_validate(s) for s in services]


@router.post(
    "/{investigation_id}/enrich/ip",
    response_model=IPEnrichmentResponse,
    summary="Run IP / ASN / RDAP Intelligence Enrichment",
    description=(
        "Enriches discovered IP addresses (extracted from A and AAAA DNS records) with "
        "Autonomous System Numbers (ASN), network prefixes, and RDAP registration metadata. "
        "Associates observations with a new ScanRun."
    ),
)
@router.post(
    "/{investigation_id}/ip-enrichment",
    response_model=IPEnrichmentResponse,
    include_in_schema=False,
)
def run_ip_enrichment(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    ip_service: IPService = Depends(get_ip_service),
    asn_service: ASNService = Depends(get_asn_service),
    rdap_service: RDAPService = Depends(get_rdap_service),
) -> IPEnrichmentResponse:
    """Execute Stage 4 IP / ASN / RDAP Intelligence Enrichment."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    target = investigation.target
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target associated with investigation not found",
        )

    target_domain = target.primary_domain
    now_utc = datetime.now(timezone.utc)

    # 1. Fetch all A and AAAA DNS records associated with subdomains under this investigation
    dns_records = db.execute(
        select(DNSRecord)
        .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
        .join(Asset, Subdomain.asset_id == Asset.id)
        .where(
            Asset.investigation_id == investigation_id,
            DNSRecord.record_type.in_(["A", "AAAA"]),
        )
    ).scalars().all()

    # 2. Extract, validate, normalize, and deduplicate IPs
    unique_ip_entries = ip_service.extract_unique_ips_from_records(dns_records)

    # 3. Initialize a new ScanRun for this IP enrichment operation
    scan_run_count = db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.investigation_id == investigation.id)
    ).scalar() or 0

    scan_run = ScanRun(
        investigation_id=investigation.id,
        run_number=scan_run_count + 1,
        status="running",
        started_at=now_utc,
    )
    db.add(scan_run)
    db.flush()

    results_detail: List[IPEnrichmentDetail] = []
    public_ips_count = 0
    skipped_non_public_count = 0
    asn_success_count = 0
    rdap_success_count = 0
    failed_count = 0

    for entry in unique_ip_entries:
        ip_str = entry["ip_address"]
        ip_version = entry["ip_version"]
        is_public = entry["is_public"]

        if not is_public:
            skipped_non_public_count += 1
            results_detail.append(
                IPEnrichmentDetail(
                    ip_address=ip_str,
                    ip_version=ip_version,
                    is_public=False,
                    status="skipped_non_public",
                    error="Non-public / reserved IP address. External ASN and RDAP queries skipped.",
                )
            )
            continue

        public_ips_count += 1

        # Step A: Perform ASN lookup
        asn_info = asn_service.lookup(ip_str)
        asn_db = None
        asn_summary: Optional[ASNSummaryResponse] = None

        if asn_info and asn_info.asn_number:
            asn_success_count += 1
            asn_db = db.execute(
                select(ASN).where(ASN.asn_number == asn_info.asn_number)
            ).scalar_one_or_none()

            if not asn_db:
                asn_db = ASN(
                    asn_number=asn_info.asn_number,
                    name=asn_info.name or f"AS{asn_info.asn_number}",
                    country=asn_info.country,
                    allocated_prefix=asn_info.allocated_prefix,
                )
                db.add(asn_db)
                db.flush()
            else:
                if asn_info.name and not asn_db.name:
                    asn_db.name = asn_info.name
                if asn_info.country and not asn_db.country:
                    asn_db.country = asn_info.country
                if asn_info.allocated_prefix and not asn_db.allocated_prefix:
                    asn_db.allocated_prefix = asn_info.allocated_prefix

            asn_summary = ASNSummaryResponse(
                id=asn_db.id,
                asn_number=asn_db.asn_number,
                name=asn_db.name,
                country=asn_db.country,
                allocated_prefix=asn_db.allocated_prefix,
            )

        # Step B: Perform RDAP lookup
        rdap_info = rdap_service.lookup(ip_str)
        rdap_summary: Optional[RDAPSummaryResponse] = None

        if rdap_info:
            rdap_success_count += 1
            rdap_summary = RDAPSummaryResponse(
                network_name=rdap_info.network_name,
                handle=rdap_info.handle,
                start_address=rdap_info.start_address,
                end_address=rdap_info.end_address,
                cidr=rdap_info.cidr,
                country=rdap_info.country,
                organization=rdap_info.organization,
                status=rdap_info.status,
                registration_date=rdap_info.registration_date,
                last_changed_date=rdap_info.last_changed_date,
            )

        # Step C: Persist / Update IP Asset
        ip_asset = db.execute(
            select(Asset).where(
                Asset.target_id == target.id,
                Asset.investigation_id == investigation.id,
                Asset.asset_type == "ip",
                Asset.value == ip_str,
            )
        ).scalar_one_or_none()

        if not ip_asset:
            ip_asset = Asset(
                target_id=target.id,
                investigation_id=investigation.id,
                asset_type="ip",
                value=ip_str,
                is_active=True,
                confidence=1.0,
                source="dns_ip_enrichment",
                tags=["ip_asset", f"ipv{ip_version}"],
                last_scan_run_id=scan_run.id,
            )
            db.add(ip_asset)
            db.flush()
        else:
            ip_asset.last_scan_run_id = scan_run.id
            ip_asset.last_seen_at = now_utc
            ip_asset.is_active = True

        # Step D: Persist / Update IPAddress entity
        ip_addr_db = db.execute(
            select(IPAddress).where(IPAddress.ip_address == ip_str)
        ).scalar_one_or_none()

        country_val = (rdap_info.country if rdap_info and rdap_info.country else None) or (
            asn_info.country if asn_info else None
        )
        org_val = (rdap_info.organization if rdap_info and rdap_info.organization else None) or (
            asn_info.name if asn_info else None
        )

        if not ip_addr_db:
            ip_addr_db = IPAddress(
                asset_id=ip_asset.id,
                ip_address=ip_str,
                ip_version=ip_version,
                asn_id=asn_db.id if asn_db else None,
                country=country_val,
                organization=org_val,
                is_active=True,
            )
            db.add(ip_addr_db)
            db.flush()
        else:
            if asn_db:
                ip_addr_db.asn_id = asn_db.id
            if country_val:
                ip_addr_db.country = country_val
            if org_val:
                ip_addr_db.organization = org_val
            ip_addr_db.is_active = True

        # Step D2: Persist point-in-time IPObservation for historical scan isolation
        existing_obs = db.execute(
            select(IPObservation).where(
                IPObservation.scan_run_id == scan_run.id,
                IPObservation.ip_address_id == ip_addr_db.id,
            )
        ).scalar_one_or_none()

        if not existing_obs:
            obs_db = IPObservation(
                scan_run_id=scan_run.id,
                ip_address_id=ip_addr_db.id,
                asn_id=asn_db.id if asn_db else None,
                observed_at=now_utc,
            )
            db.add(obs_db)
            db.flush()

        # Step E: Persist Cryptographic Evidence for RDAP payload if available
        if rdap_info and rdap_info.raw_json_str:
            ref_count = db.execute(select(func.count(Evidence.id))).scalar() or 0
            ref_code = f"EV-{now_utc.strftime('%Y%m%d')}-{ref_count + 1:05d}"
            sha_hash = Evidence.compute_sha256(rdap_info.raw_json_str)

            evidence = Evidence(
                reference_code=ref_code,
                investigation_id=investigation.id,
                asset_id=ip_asset.id,
                scan_run_id=scan_run.id,
                evidence_type="rdap",
                source="rdap_bootstrap",
                raw_payload=rdap_info.raw_json_str,
                sha256_hash=sha_hash,
                collected_at=now_utc,
                verified_integrity=True,
            )
            db.add(evidence)
            db.flush()

        detail_status = "enriched" if (asn_summary or rdap_summary) else "failed"
        if detail_status == "failed":
            failed_count += 1

        results_detail.append(
            IPEnrichmentDetail(
                ip_address=ip_str,
                ip_version=ip_version,
                is_public=True,
                status=detail_status,
                asn=asn_summary,
                rdap=rdap_summary,
                error=None if detail_status == "enriched" else "External ASN and RDAP lookup failed or returned no data",
            )
        )

    # 4. Finalize ScanRun
    scan_run.status = "completed"
    scan_run.completed_at = datetime.now(timezone.utc)
    scan_run.total_discovered_assets = len(unique_ip_entries)
    scan_run.summary = {
        "source": "ip_enrichment",
        "ips_processed": len(unique_ip_entries),
        "public_ips": public_ips_count,
        "skipped_non_public": skipped_non_public_count,
        "asn_success": asn_success_count,
        "rdap_success": rdap_success_count,
        "failed": failed_count,
    }

    # Update Investigation
    investigation.status = "active"
    db.commit()

    logger.info(
        f"Completed IP enrichment for '{target_domain}' (Investigation {investigation_id}): "
        f"{len(unique_ip_entries)} IPs processed ({public_ips_count} public, {skipped_non_public_count} skipped, "
        f"{asn_success_count} ASN, {rdap_success_count} RDAP)."
    )

    return IPEnrichmentResponse(
        investigation_id=investigation.id,
        scan_run_id=scan_run.id,
        target_domain=target_domain,
        ips_processed=len(unique_ip_entries),
        public_ips=public_ips_count,
        skipped_non_public=skipped_non_public_count,
        asn_success=asn_success_count,
        rdap_success=rdap_success_count,
        failed=failed_count,
        results=results_detail,
        completed_at=scan_run.completed_at,
    )


@router.get(
    "/{investigation_id}/ip-addresses",
    response_model=List[IPAddressSummaryResponse],
    summary="List Discovered IP Addresses for Investigation",
    description="Returns all normalized IP addresses with ASN and geolocation/organization details under this investigation.",
)
def list_investigation_ip_addresses(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[IPAddressSummaryResponse]:
    """Retrieve IP address assets and associated ASN metadata for an investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    ip_records = db.execute(
        select(IPAddress)
        .join(Asset, IPAddress.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(IPAddress.ip_address.asc())
    ).scalars().all()

    summaries: List[IPAddressSummaryResponse] = []
    for ip_rec in ip_records:
        asn_summary = None
        if ip_rec.asn:
            asn_summary = ASNSummaryResponse(
                id=ip_rec.asn.id,
                asn_number=ip_rec.asn.asn_number,
                name=ip_rec.asn.name,
                country=ip_rec.asn.country,
                allocated_prefix=ip_rec.asn.allocated_prefix,
            )

        summaries.append(
            IPAddressSummaryResponse(
                id=ip_rec.id,
                asset_id=ip_rec.asset_id,
                ip_address=ip_rec.ip_address,
                ip_version=ip_rec.ip_version,
                reverse_dns=ip_rec.reverse_dns,
                asn_id=ip_rec.asn_id,
                asn=asn_summary,
                country=ip_rec.country,
                region=ip_rec.region,
                organization=ip_rec.organization,
                is_active=ip_rec.is_active,
                last_scan_run_id=ip_rec.asset.last_scan_run_id if ip_rec.asset else None,
            )
        )

    return summaries


@router.get(
    "/{investigation_id}/ip-observations",
    response_model=List[IPObservationSummaryResponse],
    summary="List Historical IP Observations for Investigation",
    description="Returns point-in-time IP-to-ASN scan observations associated with ScanRuns under this investigation.",
)
def list_investigation_ip_observations(
    investigation_id: uuid.UUID,
    scan_run_id: Optional[uuid.UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[IPObservationSummaryResponse]:
    """Retrieve historical IPObservation records for an investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    query = (
        select(IPObservation)
        .join(ScanRun, IPObservation.scan_run_id == ScanRun.id)
        .where(ScanRun.investigation_id == investigation_id)
        .order_by(IPObservation.observed_at.desc())
    )
    if scan_run_id:
        query = query.where(IPObservation.scan_run_id == scan_run_id)

    observations = db.execute(query).scalars().all()

    return [
        IPObservationSummaryResponse(
            id=obs.id,
            scan_run_id=obs.scan_run_id,
            ip_address_id=obs.ip_address_id,
            ip_address=obs.ip_address.ip_address if obs.ip_address else None,
            asn_id=obs.asn_id,
            asn_number=obs.asn.asn_number if obs.asn else None,
            asn_name=obs.asn.name if obs.asn else None,
            observed_at=obs.observed_at,
        )
        for obs in observations
    ]


@router.get(
    "/{investigation_id}/asns",
    response_model=List[ASNSummaryResponse],
    summary="List Discovered Autonomous Systems for Investigation",
    description="Returns all unique Autonomous System Numbers (ASNs) observed for IP addresses in this investigation.",
)
def list_investigation_asns(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[ASNSummaryResponse]:
    """Retrieve distinct ASNs observed across IP addresses in the investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    # Query distinct ASNs associated with IPs in this investigation
    asn_rows = db.execute(
        select(ASN, func.count(IPAddress.id).label("ip_count"))
        .join(IPAddress, IPAddress.asn_id == ASN.id)
        .join(Asset, IPAddress.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .group_by(ASN.id)
        .order_by(ASN.asn_number.asc())
    ).all()

    return [
        ASNSummaryResponse(
            id=asn.id,
            asn_number=asn.asn_number,
            name=asn.name,
            country=asn.country,
            allocated_prefix=asn.allocated_prefix,
            ip_count=ip_count,
        )
        for asn, ip_count in asn_rows
    ]

