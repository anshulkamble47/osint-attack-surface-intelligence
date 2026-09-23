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
from backend.app.models.asset import Asset, Domain, Subdomain
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationResponse,
    CTDiscoveryResponse,
    CertificateSummaryResponse,
    AssetSummaryResponse,
)
from backend.app.services.ct_service import CTService, CTProviderError


def get_ct_service() -> CTService:
    """Dependency provider returning CTService instance."""
    return CTService()


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
