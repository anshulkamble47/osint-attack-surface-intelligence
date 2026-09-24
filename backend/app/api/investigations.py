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
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
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
    TechnologySummaryResponse,
    SecurityHeaderDetail,
    SecurityHeadersSummaryResponse,
    TLSMetadataSummaryResponse,
    ServiceFingerprintDetail,
    FingerprintResponse,
    KEVDetailResponse,
    VulnerabilityCorrelationDetail,
    CorrelateVulnerabilitiesResponse,
)
from backend.app.services.ct_service import CTService, CTProviderError
from backend.app.services.dns_service import DNSService
from backend.app.services.reachability_service import ReachabilityService
from backend.app.services.ip_service import IPService
from backend.app.services.asn_service import ASNService
from backend.app.services.rdap_service import RDAPService
from backend.app.services.http_service import HTTPIntelligenceService
from backend.app.services.technology_service import TechnologyService
from backend.app.services.vulnerability_service import VulnerabilityService


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


def get_http_intelligence_service() -> HTTPIntelligenceService:
    """Dependency provider returning HTTPIntelligenceService instance."""
    return HTTPIntelligenceService()


def get_technology_service() -> TechnologyService:
    """Dependency provider returning TechnologyService instance."""
    return TechnologyService()


def get_vulnerability_service() -> VulnerabilityService:
    """Dependency provider returning VulnerabilityService instance."""
    return VulnerabilityService()



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


@router.post(
    "/{investigation_id}/fingerprint",
    response_model=FingerprintResponse,
    summary="Run Technology Fingerprinting & HTTP Security Intelligence",
    description=(
        "Passively inspects reachable HTTP/HTTPS web services discovered for this investigation, "
        "analyzing HTTP response headers, meta markers, cookies, script tags to detect technologies, "
        "evaluating passive HTTP security headers, collecting safe TLS session metadata for HTTPS endpoints, "
        "and recording point-in-time observations linked to a new ScanRun."
    ),
)
def run_fingerprinting(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    http_service: HTTPIntelligenceService = Depends(get_http_intelligence_service),
    tech_service: TechnologyService = Depends(get_technology_service),
) -> FingerprintResponse:
    """Execute Stage 5 Technology Fingerprinting & HTTP Security Intelligence."""
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

    # 1. Start a new ScanRun for this fingerprinting run
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

    # 2. Retrieve candidate / resolving assets (domains & subdomains)
    assets = db.execute(
        select(Asset)
        .where(
            Asset.investigation_id == investigation.id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
        .order_by(Asset.value.asc())
    ).scalars().all()

    results_detail: List[ServiceFingerprintDetail] = []
    services_processed_count = 0
    reachable_count = 0
    total_techs_count = 0
    total_headers_analyzed_count = 0
    total_tls_count = 0

    ports_to_probe = [
        (80, "tcp", "http"),
        (443, "tcp", "https"),
    ]

    for asset in assets:
        hostname = asset.value

        # Fetch resolved A/AAAA IP records for pre-flight SSRF protection
        dns_records = db.execute(
            select(DNSRecord)
            .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
            .where(
                Subdomain.asset_id == asset.id,
                DNSRecord.record_type.in_(["A", "AAAA"]),
            )
        ).scalars().all()

        resolved_ips = [r.value for r in dns_records if r.value]

        # Probe each web port
        for port, protocol, service_name in ports_to_probe:
            services_processed_count += 1

            obs = http_service.probe_service(
                hostname=hostname,
                port=port,
                protocol=protocol,
                service_name=service_name,
                resolved_ips=resolved_ips if resolved_ips else None,
            )

            if not obs.is_reachable:
                # Unreachable or SSRF-blocked service
                continue

            reachable_count += 1

            # Create or link ServiceExposure record for this ScanRun
            svc_db = ServiceExposure(
                asset_id=asset.id,
                scan_run_id=scan_run.id,
                port=port,
                protocol=protocol,
                service_name=service_name,
                http_status=obs.status_code,
                page_title=obs.page_title,
                tls_version=obs.tls_metadata.tls_version if obs.tls_metadata else None,
                security_headers={
                    k: {
                        "header_name": v.header_name,
                        "present": v.present,
                        "value": v.value,
                        "status": v.status,
                        "interpretation": v.interpretation,
                    }
                    for k, v in obs.security_headers.items()
                },
                banner=obs.server_header,
                observed_at=obs.observed_at,
            )
            db.add(svc_db)
            db.flush()

            # Technology detection
            detected_techs = tech_service.fingerprint_http_observation(obs)
            tech_summaries: List[TechnologySummaryResponse] = []

            for dt in detected_techs:
                total_techs_count += 1
                tech_db = Technology(
                    asset_id=asset.id,
                    service_id=svc_db.id,
                    scan_run_id=scan_run.id,
                    name=dt.name,
                    version=dt.version,
                    cpe=dt.cpe,
                    category=dt.category,
                    confidence=dt.confidence,
                    evidence_source=dt.evidence_source,
                    detected_at=obs.observed_at,
                )
                db.add(tech_db)
                db.flush()

                tech_summaries.append(
                    TechnologySummaryResponse(
                        id=tech_db.id,
                        asset_id=asset.id,
                        asset_value=hostname,
                        service_id=svc_db.id,
                        scan_run_id=scan_run.id,
                        name=tech_db.name,
                        version=tech_db.version,
                        cpe=tech_db.cpe,
                        category=tech_db.category,
                        confidence=tech_db.confidence,
                        evidence_source=tech_db.evidence_source,
                        detected_at=tech_db.detected_at,
                    )
                )

            # Security Headers Summary
            sec_headers_dict: Dict[str, SecurityHeaderDetail] = {}
            for k, v in obs.security_headers.items():
                sec_headers_dict[k] = SecurityHeaderDetail(
                    header_name=v.header_name,
                    present=v.present,
                    value=v.value,
                    status=v.status,
                    interpretation=v.interpretation,
                )
            total_headers_analyzed_count += len(sec_headers_dict)

            sec_summary = SecurityHeadersSummaryResponse(
                service_id=svc_db.id,
                asset_id=asset.id,
                asset_value=hostname,
                url=obs.url,
                port=port,
                protocol=protocol,
                service_name=service_name,
                http_status=obs.status_code,
                headers=sec_headers_dict,
                scan_run_id=scan_run.id,
                observed_at=obs.observed_at,
            )

            # TLS Metadata Summary (HTTPS only)
            tls_summary: Optional[TLSMetadataSummaryResponse] = None
            if obs.tls_metadata and service_name == "https":
                total_tls_count += 1
                tls_summary = TLSMetadataSummaryResponse(
                    service_id=svc_db.id,
                    asset_id=asset.id,
                    asset_value=hostname,
                    url=obs.url,
                    tls_version=obs.tls_metadata.tls_version,
                    cipher_suite=obs.tls_metadata.cipher_suite,
                    cert_subject=obs.tls_metadata.cert_subject,
                    cert_issuer=obs.tls_metadata.cert_issuer,
                    cert_valid_from=obs.tls_metadata.cert_valid_from,
                    cert_valid_to=obs.tls_metadata.cert_valid_to,
                    cert_san_list=obs.tls_metadata.cert_san_list,
                    scan_run_id=scan_run.id,
                    observed_at=obs.observed_at,
                )

            results_detail.append(
                ServiceFingerprintDetail(
                    service_id=svc_db.id,
                    asset_id=asset.id,
                    hostname=hostname,
                    url=obs.url,
                    port=port,
                    service_name=service_name,
                    is_reachable=True,
                    status_code=obs.status_code,
                    page_title=obs.page_title,
                    technologies_count=len(tech_summaries),
                    technologies=tech_summaries,
                    security_headers=sec_summary,
                    tls_metadata=tls_summary,
                    error=obs.error,
                )
            )

    # 3. Finalize ScanRun
    scan_run.status = "completed"
    scan_run.completed_at = datetime.now(timezone.utc)
    scan_run.total_discovered_assets = reachable_count
    scan_run.summary = {
        "operation": "technology_fingerprinting_http_security",
        "services_processed": services_processed_count,
        "reachable": reachable_count,
        "technologies_detected": total_techs_count,
        "security_headers_analyzed": total_headers_analyzed_count,
        "tls_observations": total_tls_count,
    }

    investigation.status = "active"
    db.commit()

    logger.info(
        f"Completed Technology & Security Fingerprinting for '{target_domain}' (Inv: {investigation_id}): "
        f"{services_processed_count} probed, {reachable_count} reachable, "
        f"{total_techs_count} technologies detected, {total_tls_count} TLS observations."
    )

    return FingerprintResponse(
        investigation_id=investigation.id,
        scan_run_id=scan_run.id,
        target_domain=target_domain,
        services_processed=services_processed_count,
        reachable=reachable_count,
        technologies_detected=total_techs_count,
        security_headers_analyzed=total_headers_analyzed_count,
        tls_observations=total_tls_count,
        results=results_detail,
        completed_at=scan_run.completed_at,
    )


@router.get(
    "/{investigation_id}/technologies",
    response_model=List[TechnologySummaryResponse],
    summary="List Observed Technologies for Investigation",
    description="Returns all point-in-time technology detections for assets under this investigation.",
)
def list_investigation_technologies(
    investigation_id: uuid.UUID,
    scan_run_id: Optional[uuid.UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[TechnologySummaryResponse]:
    """Retrieve observed technologies for an investigation, optionally filtered by ScanRun."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    query = (
        select(Technology)
        .join(Asset, Technology.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(Technology.detected_at.desc())
    )
    if scan_run_id:
        query = query.where(Technology.scan_run_id == scan_run_id)

    technologies = db.execute(query).scalars().all()

    return [
        TechnologySummaryResponse(
            id=t.id,
            asset_id=t.asset_id,
            asset_value=t.asset.value if t.asset else None,
            service_id=t.service_id,
            scan_run_id=t.scan_run_id,
            name=t.name,
            version=t.version,
            cpe=t.cpe,
            category=t.category,
            confidence=t.confidence,
            evidence_source=t.evidence_source,
            detected_at=t.detected_at,
        )
        for t in technologies
    ]


@router.get(
    "/{investigation_id}/security-headers",
    response_model=List[SecurityHeadersSummaryResponse],
    summary="List HTTP Security Headers Observations for Investigation",
    description="Returns HTTP security header observations across web service exposures for this investigation.",
)
def list_investigation_security_headers(
    investigation_id: uuid.UUID,
    scan_run_id: Optional[uuid.UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[SecurityHeadersSummaryResponse]:
    """Retrieve security headers observations for an investigation, optionally filtered by ScanRun."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    query = (
        select(ServiceExposure)
        .join(Asset, ServiceExposure.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(ServiceExposure.observed_at.desc())
    )
    if scan_run_id:
        query = query.where(ServiceExposure.scan_run_id == scan_run_id)

    services = db.execute(query).scalars().all()

    summaries: List[SecurityHeadersSummaryResponse] = []
    for svc in services:
        if not svc.security_headers:
            continue

        headers_dict: Dict[str, SecurityHeaderDetail] = {}
        for h_key, h_data in svc.security_headers.items():
            if isinstance(h_data, dict):
                headers_dict[h_key] = SecurityHeaderDetail(
                    header_name=h_data.get("header_name", h_key),
                    present=h_data.get("present", False),
                    value=h_data.get("value"),
                    status=h_data.get("status", "missing"),
                    interpretation=h_data.get("interpretation", ""),
                )

        host_val = svc.asset.value if svc.asset else ""
        proto = svc.service_name or ("https" if svc.port == 443 else "http")
        url_val = f"{proto}://{host_val}:{svc.port}" if (
            (proto == "http" and svc.port != 80) or (proto == "https" and svc.port != 443)
        ) else f"{proto}://{host_val}"

        summaries.append(
            SecurityHeadersSummaryResponse(
                service_id=svc.id,
                asset_id=svc.asset_id,
                asset_value=host_val,
                url=url_val,
                port=svc.port,
                protocol=svc.protocol,
                service_name=svc.service_name,
                http_status=svc.http_status,
                headers=headers_dict,
                scan_run_id=svc.scan_run_id,
                observed_at=svc.observed_at,
            )
        )

    return summaries


@router.get(
    "/{investigation_id}/tls-metadata",
    response_model=List[TLSMetadataSummaryResponse],
    summary="List TLS Metadata Observations for Investigation",
    description="Returns TLS versions and certificate metadata for HTTPS services under this investigation.",
)
def list_investigation_tls_metadata(
    investigation_id: uuid.UUID,
    scan_run_id: Optional[uuid.UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[TLSMetadataSummaryResponse]:
    """Retrieve TLS metadata observations for HTTPS services in an investigation."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    query = (
        select(ServiceExposure)
        .join(Asset, ServiceExposure.asset_id == Asset.id)
        .where(
            Asset.investigation_id == investigation_id,
            ServiceExposure.port == 443,
        )
        .order_by(ServiceExposure.observed_at.desc())
    )
    if scan_run_id:
        query = query.where(ServiceExposure.scan_run_id == scan_run_id)

    services = db.execute(query).scalars().all()

    summaries: List[TLSMetadataSummaryResponse] = []
    for svc in services:
        if not svc.tls_version:
            continue

        host_val = svc.asset.value if svc.asset else ""
        url_val = f"https://{host_val}"

        summaries.append(
            TLSMetadataSummaryResponse(
                service_id=svc.id,
                asset_id=svc.asset_id,
                asset_value=host_val,
                url=url_val,
                tls_version=svc.tls_version,
                cipher_suite=None,
                cert_subject=None,
                cert_issuer=None,
                cert_valid_from=None,
                cert_valid_to=None,
                cert_san_list=[],
                scan_run_id=svc.scan_run_id,
                observed_at=svc.observed_at,
            )
        )

    return summaries


@router.post(
    "/{investigation_id}/vulnerabilities/correlate",
    response_model=CorrelateVulnerabilitiesResponse,
    summary="Correlate Technologies with Vulnerability & CVE Intelligence",
    description=(
        "Correlates detected technologies and versions with NVD CVE advisories and CISA KEV catalog. "
        "Matches are marked as potential matches requiring verification."
    ),
)
def correlate_investigation_vulnerabilities(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    vuln_service: VulnerabilityService = Depends(get_vulnerability_service),
) -> CorrelateVulnerabilitiesResponse:
    """Execute Stage 6 Vulnerability Intelligence & CVE Correlation."""
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

    # 1. Start a new ScanRun for this vulnerability intelligence correlation
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

    # 2. Execute correlation across observed technologies
    correlations = vuln_service.correlate_investigation_technologies(
        investigation_id=investigation_id,
        db=db,
        scan_run=scan_run,
    )

    # 3. Compile summary metrics
    tech_count = db.execute(
        select(func.count(Technology.id))
        .join(Asset, Technology.asset_id == Asset.id)
        .where(Asset.investigation_id == investigation_id)
    ).scalar() or 0

    potential_matches_count = sum(
        1 for c in correlations if c.correlation_status == "POTENTIAL_MATCH"
    )
    kev_count = sum(1 for c in correlations if c.is_kev)
    req_verif_count = sum(
        1 for c in correlations if c.correlation_status == "REQUIRES_VERIFICATION"
    )

    # 4. Finalize ScanRun
    scan_run.status = "completed"
    scan_run.completed_at = datetime.now(timezone.utc)
    scan_run.total_findings = len(correlations)
    scan_run.summary = {
        "operation": "vulnerability_intelligence_cve_correlation",
        "technologies_analyzed": tech_count,
        "cves_correlated": len(correlations),
        "potential_matches": potential_matches_count,
        "kev_listed_cves": kev_count,
        "requires_verification": req_verif_count,
    }

    investigation.status = "active"
    db.commit()

    # 5. Format response details
    details: List[VulnerabilityCorrelationDetail] = []
    for c in correlations:
        tech_rec = db.get(Technology, c.technology_id)
        asset_val = tech_rec.asset.value if tech_rec and tech_rec.asset else target_domain
        asset_id_val = tech_rec.asset_id if tech_rec else target.id

        kev_dto = None
        if c.kev_details:
            kev_dto = KEVDetailResponse(
                vendor_project=c.kev_details.vendor_project,
                product=c.kev_details.product,
                vulnerability_name=c.kev_details.vulnerability_name,
                date_added=c.kev_details.date_added,
                required_action=c.kev_details.required_action,
                due_date=c.kev_details.due_date,
                ransomware_campaign=c.kev_details.known_ransomware_campaign_use,
            )

        # Retrieve DB TechnologyVulnerability ID if available
        tv_id = uuid.uuid4()
        if tech_rec:
            tv_rec = db.execute(
                select(TechnologyVulnerability)
                .join(Vulnerability, TechnologyVulnerability.vulnerability_id == Vulnerability.id)
                .where(
                    TechnologyVulnerability.technology_id == tech_rec.id,
                    Vulnerability.cve_id == c.cve_id,
                )
            ).scalar_one_or_none()
            if tv_rec:
                tv_id = tv_rec.id

        details.append(
            VulnerabilityCorrelationDetail(
                id=tv_id,
                technology_id=c.technology_id,
                technology_name=c.technology_name,
                observed_version=c.observed_version,
                asset_id=asset_id_val,
                asset_value=asset_val,
                cve_id=c.cve_id,
                title=c.title,
                description=c.description,
                severity=c.severity,
                cvss_score=c.cvss_score,
                cvss_vector=c.cvss_vector,
                is_kev=c.is_kev,
                kev_details=kev_dto,
                correlation_status=c.correlation_status,
                match_confidence=c.match_confidence,
                match_basis=c.match_basis,
                source=c.source,
                published_date=c.published_date,
                scan_run_id=scan_run.id,
                created_at=now_utc,
            )
        )

    return CorrelateVulnerabilitiesResponse(
        investigation_id=investigation.id,
        scan_run_id=scan_run.id,
        target_domain=target_domain,
        technologies_analyzed=tech_count,
        cves_correlated=len(correlations),
        potential_matches=potential_matches_count,
        kev_listed_cves=kev_count,
        requires_verification=req_verif_count,
        results=details,
        completed_at=scan_run.completed_at,
    )


@router.get(
    "/{investigation_id}/vulnerabilities",
    response_model=List[VulnerabilityCorrelationDetail],
    summary="List Correlated Vulnerabilities for Investigation",
    description="Retrieves passive CVE intelligence and technology correlations for an investigation.",
)
def list_investigation_vulnerabilities(
    investigation_id: uuid.UUID,
    scan_run_id: Optional[uuid.UUID] = None,
    technology: Optional[str] = None,
    cve_id: Optional[str] = None,
    is_kev: Optional[bool] = None,
    verification_status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> List[VulnerabilityCorrelationDetail]:
    """Retrieve correlated vulnerabilities for an investigation with optional filtering."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    _check_investigation_access(investigation, current_user)

    query = (
        select(TechnologyVulnerability)
        .join(Technology, TechnologyVulnerability.technology_id == Technology.id)
        .join(Asset, Technology.asset_id == Asset.id)
        .join(Vulnerability, TechnologyVulnerability.vulnerability_id == Vulnerability.id)
        .where(Asset.investigation_id == investigation_id)
        .order_by(TechnologyVulnerability.created_at.desc())
    )

    if scan_run_id:
        query = query.where(Technology.scan_run_id == scan_run_id)

    if technology:
        query = query.where(Technology.name.ilike(f"%{technology}%"))

    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))

    if verification_status:
        query = query.where(
            TechnologyVulnerability.verification_status == verification_status.lower()
        )

    results = db.execute(query).scalars().all()

    items: List[VulnerabilityCorrelationDetail] = []
    for tv in results:
        notes_data: Dict[str, Any] = {}
        if tv.notes:
            try:
                notes_data = json.loads(tv.notes)
            except Exception:
                notes_data = {"match_basis": tv.notes}

        kev_flag = notes_data.get("is_kev", False)
        if is_kev is not None and kev_flag != is_kev:
            continue

        kev_info = None
        if notes_data.get("kev_details"):
            kd = notes_data["kev_details"]
            kev_info = KEVDetailResponse(
                vendor_project=kd.get("vendor_project", "Unknown"),
                product=kd.get("product", "Unknown"),
                vulnerability_name=kd.get("vulnerability_name", ""),
                date_added=kd.get("date_added"),
                required_action=kd.get("required_action", ""),
                due_date=kd.get("due_date"),
                ransomware_campaign=kd.get("ransomware_campaign", "Unknown"),
            )

        items.append(
            VulnerabilityCorrelationDetail(
                id=tv.id,
                technology_id=tv.technology_id,
                technology_name=tv.technology.name if tv.technology else "",
                observed_version=tv.technology.version if tv.technology else None,
                asset_id=tv.technology.asset_id if tv.technology else tv.id,
                asset_value=tv.technology.asset.value if tv.technology and tv.technology.asset else None,
                cve_id=tv.vulnerability.cve_id if tv.vulnerability else "",
                title=tv.vulnerability.title if tv.vulnerability else None,
                description=tv.vulnerability.description if tv.vulnerability else "",
                severity=tv.vulnerability.severity if tv.vulnerability else "UNKNOWN",
                cvss_score=tv.vulnerability.cvss_v3_score if tv.vulnerability else None,
                cvss_vector=tv.vulnerability.cvss_vector if tv.vulnerability else None,
                is_kev=kev_flag,
                kev_details=kev_info,
                correlation_status=notes_data.get(
                    "correlation_status", tv.verification_status.upper()
                ),
                match_confidence=tv.match_confidence,
                match_basis=notes_data.get("match_basis", "CPE / Version correlation"),
                source=tv.vulnerability.source if tv.vulnerability else "NVD",
                published_date=tv.vulnerability.published_date if tv.vulnerability else None,
                scan_run_id=tv.technology.scan_run_id if tv.technology else None,
                created_at=tv.created_at,
            )
        )

    return items



