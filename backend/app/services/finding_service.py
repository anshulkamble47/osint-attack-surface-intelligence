"""Deterministic Findings, Contextual Risk Scoring, and Evidence Intelligence Service."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import select, and_, func
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.investigation import Investigation, ScanRun
from backend.app.models.asset import Asset, Subdomain, Domain, ServiceExposure
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.finding import Finding
from backend.app.models.evidence import Evidence
from backend.app.schemas.finding import (
    FindingAssetSummary,
    FindingTechnologySummary,
    FindingVulnerabilitySummary,
    FindingEvidenceSummary,
    FindingResponse,
    GenerateFindingsResponse,
    FindingListResponse,
)


class FindingService:
    """
    Deterministic Findings, Contextual Risk Scoring, and Evidence Intelligence Service.
    Consumes intelligence produced by Stages 3-7 and produces explainable, evidence-backed security findings.
    """

    @staticmethod
    def calculate_risk_score(
        base_severity: str,
        cvss_score: Optional[float] = None,
        is_kev: bool = False,
        is_exposed: bool = False,
        tech_confidence: float = 0.8,
        finding_type: str = "VULNERABILITY",
    ) -> Tuple[int, str, Dict[str, Any]]:
        """
        Transparent factor-based contextual risk scoring formula.
        Guarantees:
        1. Fully bounded: 0 <= risk_score <= 100
        2. Deterministic & reproducible
        3. Explainable factor breakdown
        4. Independent from raw CVSS base score
        """
        # 1. Base Score calculation
        if cvss_score is not None:
            # Bound CVSS to 0.0 - 10.0 and map to 0 - 100
            clamped_cvss = max(0.0, min(10.0, float(cvss_score)))
            base_score = int(round(clamped_cvss * 10))
            base_factor = f"CVSS v3 base score {clamped_cvss:.1f} mapped to baseline {base_score}/100"
        else:
            # Severity mapping fallback
            sev_map = {
                "CRITICAL": 75,
                "HIGH": 60,
                "MEDIUM": 40,
                "LOW": 20,
                "INFO": 5,
            }
            base_score = sev_map.get(base_severity.upper(), 20)
            base_factor = f"Finding severity '{base_severity.upper()}' mapped to baseline {base_score}/100"

        # 2. CISA KEV Adjustment (+15)
        kev_adjustment = 0
        kev_reason = "Not cataloged in CISA KEV"
        if is_kev:
            kev_adjustment = 15
            kev_reason = "Vulnerability listed in CISA Known Exploited Vulnerabilities (KEV) catalog (elevated in-the-wild exploitation probability)"

        # 3. Internet Exposure Adjustment (+10)
        exposure_adjustment = 0
        exposure_reason = "Component is internal or reachability unconfirmed"
        if is_exposed:
            exposure_adjustment = 10
            exposure_reason = "Affected component is externally observable and reachable over public network interface"

        # 4. Correlation Confidence Adjustment (+5 / -10)
        confidence_adjustment = 0
        confidence_reason = f"Standard confidence technology match ({tech_confidence:.2f})"
        if tech_confidence >= 0.90:
            confidence_adjustment = 5
            confidence_reason = f"High-confidence technology fingerprint match ({tech_confidence:.2f})"
        elif tech_confidence <= 0.60:
            confidence_adjustment = -10
            confidence_reason = f"Lower-confidence or version-range technology match ({tech_confidence:.2f})"

        # 5. Calculate raw and bounded score
        raw_score = base_score + kev_adjustment + exposure_adjustment + confidence_adjustment
        final_score = max(0, min(100, int(round(raw_score))))

        # 6. Derive Platform Risk Category
        if final_score >= 80:
            risk_category = "CRITICAL"
        elif final_score >= 60:
            risk_category = "HIGH"
        elif final_score >= 40:
            risk_category = "MEDIUM"
        elif final_score >= 20:
            risk_category = "LOW"
        else:
            risk_category = "INFORMATIONAL"

        risk_factors = {
            "base_score": base_score,
            "base_factor": base_factor,
            "cisa_kev_adjustment": kev_adjustment,
            "cisa_kev_reason": kev_reason,
            "exposure_adjustment": exposure_adjustment,
            "exposure_reason": exposure_reason,
            "confidence_adjustment": confidence_adjustment,
            "confidence_reason": confidence_reason,
            "raw_score": raw_score,
            "final_score": final_score,
            "risk_category": risk_category,
        }

        return final_score, risk_category, risk_factors

    @staticmethod
    def _generate_finding_reference_code(db: Session, investigation_id: uuid.UUID, index: int) -> str:
        """Generate a stable, human-readable finding reference code."""
        inv = db.get(Investigation, investigation_id)
        ref_base = inv.reference_code if inv else f"INV-{uuid.uuid4().hex[:6].upper()}"
        return f"F-{ref_base}-{index:04d}"

    def generate_investigation_findings(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        scan_run_id: Optional[uuid.UUID] = None,
    ) -> GenerateFindingsResponse:
        """
        Generate explicit, evidence-backed security findings for an investigation.
        Idempotent: updates existing finding records or inserts new ones without duplication.
        Scoped to ScanRun for historical isolation.
        """
        investigation = db.get(Investigation, investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")

        # Determine target ScanRun
        target_scan_run: Optional[ScanRun] = None
        if scan_run_id:
            target_scan_run = db.get(ScanRun, scan_run_id)
            if not target_scan_run or target_scan_run.investigation_id != investigation_id:
                raise ValueError("ScanRun does not belong to the requested investigation")
        else:
            target_scan_run = (
                db.execute(
                    select(ScanRun)
                    .where(ScanRun.investigation_id == investigation_id)
                    .order_by(ScanRun.run_number.desc())
                )
                .scalars()
                .first()
            )

        resolved_scan_run_id = target_scan_run.id if target_scan_run else None
        scan_run_number = target_scan_run.run_number if target_scan_run else None

        # Fetch existing findings to enable idempotency and prevent duplicates
        existing_findings_query = select(Finding).where(
            Finding.investigation_id == investigation_id
        )
        if resolved_scan_run_id:
            existing_findings_query = existing_findings_query.where(
                Finding.scan_run_id == resolved_scan_run_id
            )
        else:
            existing_findings_query = existing_findings_query.where(
                Finding.scan_run_id.is_(None)
            )

        existing_findings = db.execute(existing_findings_query).scalars().all()
        findings_by_key: Dict[str, Finding] = {
            f"{f.asset_id}_{f.category}_{f.title}": f for f in existing_findings
        }

        created_count = 0
        updated_count = 0
        findings_to_return: List[Finding] = []
        finding_code_seq = len(existing_findings) + 1

        # -------------------------------------------------------------
        # 1. VULNERABILITY FINDINGS (Stage 6 TechnologyVulnerabilities)
        # -------------------------------------------------------------
        tv_query = (
            select(TechnologyVulnerability)
            .join(Technology, TechnologyVulnerability.technology_id == Technology.id)
            .join(Asset, Technology.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        if resolved_scan_run_id:
            tv_query = tv_query.where(Technology.scan_run_id == resolved_scan_run_id)

        tech_vulns = db.execute(tv_query).scalars().all()

        for tv in tech_vulns:
            tech = db.get(Technology, tv.technology_id)
            vuln = db.get(Vulnerability, tv.vulnerability_id)
            if not tech or not vuln:
                continue

            asset = db.get(Asset, tech.asset_id)
            if not asset:
                continue

            # Check if affected service is exposed
            is_exposed = False
            if tech.service_id:
                svc = db.get(ServiceExposure, tech.service_id)
                if svc and svc.http_status and svc.http_status < 500:
                    is_exposed = True

            # Check CISA KEV listing
            is_kev = False
            if tv.notes and "cisa_kev" in tv.notes.lower():
                is_kev = True
            elif vuln.references:
                for ref in vuln.references:
                    if isinstance(ref, dict) and "cisa.gov" in str(ref.get("url", "")).lower():
                        is_kev = True
                        break

            # Calculate risk score and factors
            risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                base_severity=vuln.severity,
                cvss_score=vuln.cvss_v3_score,
                is_kev=is_kev,
                is_exposed=is_exposed,
                tech_confidence=tech.confidence,
                finding_type="VULNERABILITY",
            )

            title = f"Potential Vulnerability: {vuln.cve_id} affecting {tech.name} {tech.version or ''}".strip()
            description = (
                f"Passive technology fingerprinting observed '{tech.name} {tech.version or ''}' on asset {asset.value}, "
                f"which correlates with vulnerability intelligence {vuln.cve_id} (Severity: {vuln.severity}, CVSS: {vuln.cvss_v3_score or 'N/A'}). "
                f"{vuln.description}"
            )
            remediation = (
                f"Upgrade '{tech.name}' to a patched, supported version or apply recommended vendor mitigations. "
                f"Refer to security advisory for {vuln.cve_id}."
            )

            finding_key = f"{asset.id}_vulnerability_{title}"
            existing = findings_by_key.get(finding_key)

            if existing:
                existing.severity = vuln.severity
                existing.context_score = risk_score
                existing.risk_factors = risk_factors
                existing.score_breakdown = risk_factors
                existing.description = description
                existing.recommendation = remediation
                existing.remediation = remediation
                existing.updated_at = datetime.now(timezone.utc)
                findings_to_return.append(existing)
                updated_count += 1
            else:
                ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                finding_code_seq += 1

                finding = Finding(
                    reference_code=ref_code,
                    investigation_id=investigation_id,
                    scan_run_id=resolved_scan_run_id,
                    asset_id=asset.id,
                    technology_id=tech.id,
                    vulnerability_id=vuln.id,
                    category="vulnerability",
                    finding_type="VULNERABILITY",
                    title=title,
                    severity=vuln.severity,
                    context_score=risk_score,
                    score_breakdown=risk_factors,
                    risk_factors=risk_factors,
                    description=description,
                    recommendation=remediation,
                    remediation=remediation,
                    is_verified=False,
                    status="open",
                )
                db.add(finding)
                findings_by_key[finding_key] = finding
                findings_to_return.append(finding)
                created_count += 1

        # -------------------------------------------------------------
        # 2. SECURITY HEADER FINDINGS (Stage 5 HTTP Security)
        # -------------------------------------------------------------
        svc_query = (
            select(ServiceExposure)
            .join(Asset, ServiceExposure.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        if resolved_scan_run_id:
            svc_query = svc_query.where(ServiceExposure.scan_run_id == resolved_scan_run_id)

        services = db.execute(svc_query).scalars().all()

        for svc in services:
            asset = db.get(Asset, svc.asset_id)
            if not asset:
                continue

            headers = svc.security_headers or {}
            is_exposed = svc.http_status is not None and svc.http_status < 500

            # Condition 1: Missing HSTS on HTTPS service
            is_https = svc.port == 443 or svc.service_name == "https" or (svc.tls_version is not None)
            hsts_header = headers.get("strict-transport-security") or headers.get("Strict-Transport-Security")
            hsts_present = bool(hsts_header and (hsts_header.get("present") if isinstance(hsts_header, dict) else True))

            if is_https and not hsts_present:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="MEDIUM",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="SECURITY_HEADER",
                )
                title = f"Missing HTTP Strict Transport Security (HSTS) on port {svc.port}"
                desc = (
                    f"The HTTPS web service on {asset.value}:{svc.port} does not emit the 'Strict-Transport-Security' response header. "
                    f"Browsers may attempt unencrypted HTTP connections, exposing traffic to SSL stripping or active network interception."
                )
                rec = "Configure the 'Strict-Transport-Security' HTTP response header with 'max-age=31536000; includeSubDomains; preload'."

                key = f"{asset.id}_security_header_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="security_header",
                        finding_type="SECURITY_HEADER",
                        title=title,
                        severity="MEDIUM",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

            # Condition 2: Missing CSP
            csp_header = headers.get("content-security-policy") or headers.get("Content-Security-Policy")
            csp_present = bool(csp_header and (csp_header.get("present") if isinstance(csp_header, dict) else True))

            if not csp_present and svc.http_status == 200:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="LOW",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="SECURITY_HEADER",
                )
                title = f"Missing Content Security Policy (CSP) Header on port {svc.port}"
                desc = (
                    f"The web application on {asset.value}:{svc.port} does not declare a 'Content-Security-Policy' header, "
                    f"increasing exposure to cross-site scripting (XSS) and content injection attacks."
                )
                rec = "Implement a restrictive 'Content-Security-Policy' header defining approved sources for scripts, styles, and frames."

                key = f"{asset.id}_security_header_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="security_header",
                        finding_type="SECURITY_HEADER",
                        title=title,
                        severity="LOW",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

            # Condition 3: Missing X-Frame-Options (Clickjacking)
            xfo_header = headers.get("x-frame-options") or headers.get("X-Frame-Options")
            xfo_present = bool(xfo_header and (xfo_header.get("present") if isinstance(xfo_header, dict) else True))

            if not xfo_present and svc.http_status == 200:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="LOW",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="SECURITY_HEADER",
                )
                title = f"Missing Anti-Clickjacking Header (X-Frame-Options) on port {svc.port}"
                desc = (
                    f"The web application on {asset.value}:{svc.port} is missing the 'X-Frame-Options' header, "
                    f"which allows malicious external sites to embed this page within an unauthorized iframe."
                )
                rec = "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."

                key = f"{asset.id}_security_header_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="security_header",
                        finding_type="SECURITY_HEADER",
                        title=title,
                        severity="LOW",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

            # Condition 4: Missing X-Content-Type-Options
            xcto_header = headers.get("x-content-type-options") or headers.get("X-Content-Type-Options")
            xcto_present = bool(xcto_header and (xcto_header.get("present") if isinstance(xcto_header, dict) else True))

            if not xcto_present and svc.http_status == 200:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="LOW",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="SECURITY_HEADER",
                )
                title = f"Missing MIME-Sniffing Protection (X-Content-Type-Options) on port {svc.port}"
                desc = (
                    f"The web application on {asset.value}:{svc.port} does not specify 'X-Content-Type-Options: nosniff', "
                    f"allowing browsers to MIME-sniff response bodies and execute untrusted user uploads as script."
                )
                rec = "Set 'X-Content-Type-Options: nosniff' on all HTTP responses."

                key = f"{asset.id}_security_header_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="security_header",
                        finding_type="SECURITY_HEADER",
                        title=title,
                        severity="LOW",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

            # -------------------------------------------------------------
            # 3. TLS PROTOCOL WEAKNESSES
            # -------------------------------------------------------------
            if svc.tls_version in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="MEDIUM",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="TLS_SECURITY",
                )
                title = f"Deprecated TLS Protocol Version ({svc.tls_version}) on port {svc.port}"
                desc = (
                    f"The service on {asset.value}:{svc.port} negotiates connections using legacy protocol version '{svc.tls_version}', "
                    f"which contains known cryptographic weaknesses and is deprecated by RFC 8996."
                )
                rec = "Disable legacy TLS versions (TLS 1.0, TLS 1.1) in web server configuration and enforce TLS 1.2 and TLS 1.3."

                key = f"{asset.id}_tls_security_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="tls_security",
                        finding_type="TLS_SECURITY",
                        title=title,
                        severity="MEDIUM",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

            # -------------------------------------------------------------
            # 4. SERVICE EXPOSURE (Cleartext HTTP on Port 80)
            # -------------------------------------------------------------
            if svc.port == 80 and svc.service_name == "http" and svc.http_status == 200:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="LOW",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=is_exposed,
                    tech_confidence=1.0,
                    finding_type="SERVICE_EXPOSURE",
                )
                title = f"Cleartext HTTP Service Exposed on Port {svc.port}"
                desc = (
                    f"The service on {asset.value}:{svc.port} serves cleartext HTTP without automatic redirection to HTTPS. "
                    f"Unencrypted user interactions are susceptible to passive eavesdropping."
                )
                rec = "Configure automatic 301 HTTP-to-HTTPS redirect for all inbound traffic on port 80."

                key = f"{asset.id}_service_exposure_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=asset.id,
                        category="service_exposure",
                        finding_type="SERVICE_EXPOSURE",
                        title=title,
                        severity="LOW",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

        # -------------------------------------------------------------
        # 5. CERTIFICATE EXCLUSIVITY & EXPIRATION (Stage 3A Certificates)
        # -------------------------------------------------------------
        cert_query = select(subdomain_certificates)
        if resolved_scan_run_id:
            cert_query = cert_query.where(
                subdomain_certificates.c.scan_run_id == resolved_scan_run_id
            )

        cert_assocs = db.execute(cert_query).all()
        for assoc in cert_assocs:
            sub = db.get(Subdomain, assoc.subdomain_id)
            cert = db.get(Certificate, assoc.certificate_id)
            if not sub or not cert:
                continue

            sub_asset = db.get(Asset, sub.asset_id)
            if not sub_asset or sub_asset.investigation_id != investigation_id:
                continue

            if cert.is_expired:
                risk_score, risk_cat, risk_factors = self.calculate_risk_score(
                    base_severity="HIGH",
                    cvss_score=None,
                    is_kev=False,
                    is_exposed=True,
                    tech_confidence=1.0,
                    finding_type="TLS_SECURITY",
                )
                title = f"Expired TLS Certificate for {cert.subject_cn}"
                desc = (
                    f"The TLS certificate for '{cert.subject_cn}' (Issuer: {cert.issuer}) associated with {sub.subdomain_name} "
                    f"expired on {cert.valid_to}. Web browsers will trigger security warnings and block connections."
                )
                rec = "Renew and replace the expired certificate with a valid certificate issued by an authorized CA."

                key = f"{sub_asset.id}_tls_security_{title}"
                existing = findings_by_key.get(key)
                if existing:
                    existing.context_score = risk_score
                    existing.risk_factors = risk_factors
                    existing.score_breakdown = risk_factors
                    existing.updated_at = datetime.now(timezone.utc)
                    findings_to_return.append(existing)
                    updated_count += 1
                else:
                    ref_code = self._generate_finding_reference_code(db, investigation_id, finding_code_seq)
                    finding_code_seq += 1
                    f = Finding(
                        reference_code=ref_code,
                        investigation_id=investigation_id,
                        scan_run_id=resolved_scan_run_id,
                        asset_id=sub_asset.id,
                        category="tls_security",
                        finding_type="TLS_SECURITY",
                        title=title,
                        severity="HIGH",
                        context_score=risk_score,
                        score_breakdown=risk_factors,
                        risk_factors=risk_factors,
                        description=desc,
                        recommendation=rec,
                        remediation=rec,
                        is_verified=True,
                        status="open",
                    )
                    db.add(f)
                    findings_by_key[key] = f
                    findings_to_return.append(f)
                    created_count += 1

        # Commit all new/updated findings
        db.commit()

        # Update ScanRun total findings count if ScanRun is active
        if target_scan_run:
            target_scan_run.total_findings = len(findings_to_return)
            db.commit()

        # Compute breakdown statistics
        sev_breakdown: Dict[str, int] = {}
        risk_breakdown: Dict[str, int] = {}
        serialized_findings: List[FindingResponse] = []

        for f in findings_to_return:
            db.refresh(f)
            sev_breakdown[f.severity] = sev_breakdown.get(f.severity, 0) + 1
            risk_cat = f.risk_factors.get("risk_category", "LOW") if f.risk_factors else "LOW"
            risk_breakdown[risk_cat] = risk_breakdown.get(risk_cat, 0) + 1
            serialized_findings.append(self._serialize_finding(f))

        return GenerateFindingsResponse(
            investigation_id=investigation_id,
            scan_run_id=resolved_scan_run_id,
            scan_run_number=scan_run_number,
            findings_generated=created_count,
            findings_updated=updated_count,
            findings_total=len(findings_to_return),
            severity_breakdown=sev_breakdown,
            risk_category_breakdown=risk_breakdown,
            findings=serialized_findings,
            completed_at=datetime.now(timezone.utc),
            note=f"Successfully correlated {len(findings_to_return)} deterministic security findings for ScanRun #{scan_run_number or 1}.",
        )

    def list_investigation_findings(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        scan_run_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        finding_type: Optional[str] = None,
        category: Optional[str] = None,
    ) -> FindingListResponse:
        """Query and filter findings for an investigation."""
        query = select(Finding).where(Finding.investigation_id == investigation_id)

        if scan_run_id:
            query = query.where(Finding.scan_run_id == scan_run_id)
        if severity:
            query = query.where(Finding.severity == severity.upper())
        if status:
            query = query.where(Finding.status == status.lower())
        if finding_type:
            query = query.where(Finding.finding_type == finding_type.upper())
        if category:
            query = query.where(Finding.category == category.lower())

        query = query.order_by(Finding.context_score.desc(), Finding.created_at.desc())
        findings = db.execute(query).scalars().all()

        sev_breakdown: Dict[str, int] = {}
        risk_breakdown: Dict[str, int] = {}
        serialized: List[FindingResponse] = []

        for f in findings:
            sev_breakdown[f.severity] = sev_breakdown.get(f.severity, 0) + 1
            risk_cat = f.risk_factors.get("risk_category", "LOW") if f.risk_factors else "LOW"
            risk_breakdown[risk_cat] = risk_breakdown.get(risk_cat, 0) + 1
            serialized.append(self._serialize_finding(f))

        return FindingListResponse(
            investigation_id=investigation_id,
            scan_run_id=scan_run_id,
            total=len(findings),
            severity_breakdown=sev_breakdown,
            risk_category_breakdown=risk_breakdown,
            findings=serialized,
        )

    def get_finding_detail(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> FindingResponse:
        """Retrieve a specific finding with full explainability details, verifying investigation ownership."""
        finding = db.get(Finding, finding_id)
        if not finding or finding.investigation_id != investigation_id:
            raise ValueError(f"Finding {finding_id} not found in this investigation")
        return self._serialize_finding(finding)

    def update_finding_status(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        finding_id: uuid.UUID,
        new_status: str,
    ) -> FindingResponse:
        """Update finding lifecycle status (open, acknowledged, resolved, suppressed)."""
        finding = db.get(Finding, finding_id)
        if not finding or finding.investigation_id != investigation_id:
            raise ValueError(f"Finding {finding_id} not found in this investigation")

        normalized_status = new_status.lower().strip()
        if normalized_status not in ["open", "acknowledged", "resolved", "suppressed"]:
            raise ValueError(f"Invalid finding status '{new_status}'")

        finding.status = normalized_status
        finding.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(finding)
        return self._serialize_finding(finding)

    @staticmethod
    def _serialize_finding(f: Finding) -> FindingResponse:
        """Convert SQLAlchemy Finding entity into standardized Pydantic FindingResponse."""
        asset_summary = None
        if f.asset:
            asset_summary = FindingAssetSummary(
                id=f.asset.id,
                asset_type=f.asset.asset_type,
                value=f.asset.value,
            )

        tech_summary = None
        if f.technology:
            tech_summary = FindingTechnologySummary(
                id=f.technology.id,
                name=f.technology.name,
                version=f.technology.version,
                cpe=f.technology.cpe,
                category=f.technology.category,
                confidence=f.technology.confidence,
            )

        vuln_summary = None
        cvss_score = None
        is_kev = False
        if f.vulnerability:
            cvss_score = f.vulnerability.cvss_v3_score
            vuln_summary = FindingVulnerabilitySummary(
                id=f.vulnerability.id,
                cve_id=f.vulnerability.cve_id,
                title=f.vulnerability.title,
                severity=f.vulnerability.severity,
                cvss_v3_score=f.vulnerability.cvss_v3_score,
                cvss_vector=f.vulnerability.cvss_vector,
                source=f.vulnerability.source,
            )

        if f.risk_factors and f.risk_factors.get("cisa_kev_adjustment", 0) > 0:
            is_kev = True

        evidence_list: List[FindingEvidenceSummary] = []
        if f.evidence_items:
            for ev in f.evidence_items:
                evidence_list.append(
                    FindingEvidenceSummary(
                        id=ev.id,
                        reference_code=ev.reference_code,
                        evidence_type=ev.evidence_type,
                        source=ev.source,
                        sha256_hash=ev.sha256_hash,
                        collected_at=ev.collected_at,
                    )
                )

        risk_cat = f.risk_factors.get("risk_category", "LOW") if f.risk_factors else "LOW"

        return FindingResponse(
            id=f.id,
            reference_code=f.reference_code,
            investigation_id=f.investigation_id,
            scan_run_id=f.scan_run_id,
            asset_id=f.asset_id,
            technology_id=f.technology_id,
            vulnerability_id=f.vulnerability_id,
            title=f.title,
            description=f.description,
            category=f.category,
            finding_type=f.finding_type or f.category.upper(),
            severity=f.severity,
            status=f.status,
            context_score=f.context_score,
            risk_score=f.context_score,
            risk_category=risk_cat,
            cvss_score=cvss_score,
            is_kev=is_kev,
            score_breakdown=f.score_breakdown or {},
            risk_factors=f.risk_factors or {},
            remediation=f.remediation or f.recommendation,
            recommendation=f.recommendation,
            is_verified=f.is_verified,
            asset=asset_summary,
            technology=tech_summary,
            vulnerability=vuln_summary,
            evidence_items=evidence_list,
            created_at=f.created_at,
            updated_at=f.updated_at,
        )
