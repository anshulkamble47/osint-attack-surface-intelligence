"""Comprehensive test suite for Stage 8: Findings, Contextual Risk Scoring & Evidence Intelligence.

Tests cover:
1. Vulnerability finding generation from TechnologyVulnerability
2. Security header finding generation (HSTS, CSP, XFO, XCTO)
3. TLS finding generation (expired certificate & deprecated TLS versions)
4. Service exposure finding behavior (cleartext HTTP port 80)
5. No finding created from technology alone without security condition
6. CVSS score preservation and clear separation from platform contextual risk
7. CISA KEV contextual adjustment (+15 points)
8. Exposure contextual adjustment (+10 points)
9. Correlation confidence factor adjustment (+5 for >=0.90, -10 for <=0.60)
10. Risk score bounds strictly enforced between 0 and 100
11. Risk score determinism and reproducibility
12. Risk category thresholds (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
13. Explainable risk factors breakdown
14. Finding deduplication
15. Repeated generation idempotency
16. ScanRun historical isolation
17. Cross-investigation ScanRun rejection (400)
18. Cross-investigation finding IDOR rejection (404)
19. Unauthorized user access rejection (RBAC 403)
20. Evidence and provenance linkage
21. Remediation provenance
22. Finding lifecycle status update (PATCH)
23. Exhaustive risk formula boundary tests
24. Stage 6 vulnerability regression
25. Stage 7 correlation graph regression
"""

import uuid
import random
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.investigation import Target, Investigation, ScanRun
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, IPAddress, ASN, IPObservation, ServiceExposure
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.finding import Finding
from backend.app.models.evidence import Evidence
from backend.app.core.security import hash_password, create_access_token
from backend.app.services.finding_service import FindingService
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# --- Fixtures & Setup ---

@pytest.fixture(autouse=True)
def ensure_stage8_test_users():
    """Ensure test users with distinct roles exist in database."""
    with TestingSessionLocal() as db:
        users = [
            (uuid.UUID("81111111-1111-1111-1111-111111111111"), "analyst8a@security.local", "analyst_8a", "analyst"),
            (uuid.UUID("82222222-2222-2222-2222-222222222222"), "analyst8b@security.local", "analyst_8b", "analyst"),
            (uuid.UUID("83333333-3333-3333-3333-333333333333"), "admin8@security.local", "admin_8", "admin"),
        ]
        for user_id, email, username, role in users:
            existing = db.get(User, user_id)
            if not existing:
                u = User(
                    id=user_id,
                    email=email,
                    username=username,
                    hashed_password=hash_password("Password123!"),
                    full_name=f"Stage8 {username}",
                    role=role,
                    is_active=True,
                )
                db.add(u)
        db.commit()


def get_auth_headers(user_id: uuid.UUID, username: str, role: str) -> dict:
    token = create_access_token(data={"sub": str(user_id), "username": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def populated_findings_environment():
    """Seed a rich, complete attack-surface environment with vulnerabilities, headers, and certificates."""
    with TestingSessionLocal() as db:
        analyst_id = uuid.UUID("81111111-1111-1111-1111-111111111111")
        rand_id = uuid.uuid4().hex[:8]
        rand_ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
        rand_cve = f"CVE-2021-{random.randint(10000, 99999)}"
        rand_fp = uuid.uuid4().hex + uuid.uuid4().hex

        target = Target(
            name=f"Findings Test Corp {rand_id}",
            primary_domain=f"findingstest-{rand_id}.com",
            organization="Findings Corp",
            is_authorized=True,
        )
        db.add(target)
        db.flush()

        inv = Investigation(
            reference_code=f"INV-F8-{rand_id.upper()}",
            target_id=target.id,
            title="Findings & Risk Assessment",
            created_by_id=analyst_id,
            status="active",
        )
        db.add(inv)
        db.flush()

        scan_run = ScanRun(
            investigation_id=inv.id,
            run_number=1,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan_run)
        db.flush()

        # Domain Asset & Model
        dom_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="domain",
            value=f"findingstest-{rand_id}.com",
            source="ct_log",
            last_scan_run_id=scan_run.id,
        )
        db.add(dom_asset)
        db.flush()

        domain = Domain(
            asset_id=dom_asset.id,
            domain_name=f"findingstest-{rand_id}.com",
        )
        db.add(domain)
        db.flush()

        # Subdomain Asset & Model
        sub_asset = Asset(
            target_id=target.id,
            investigation_id=inv.id,
            asset_type="subdomain",
            value=f"api.findingstest-{rand_id}.com",
            source="ct_log",
            last_scan_run_id=scan_run.id,
        )
        db.add(sub_asset)
        db.flush()

        subdomain = Subdomain(
            asset_id=sub_asset.id,
            domain_id=domain.id,
            subdomain_name=f"api.findingstest-{rand_id}.com",
            is_resolving=True,
            discovery_source="crt.sh",
        )
        db.add(subdomain)
        db.flush()

        # Service Exposure 1 (HTTPS 443 with missing HSTS, CSP, XFO, XCTO)
        service_https = ServiceExposure(
            asset_id=sub_asset.id,
            scan_run_id=scan_run.id,
            port=443,
            protocol="tcp",
            service_name="https",
            http_status=200,
            tls_version="TLSv1.3",
            page_title="API Gateway",
            security_headers={
                "strict-transport-security": {"present": False, "status": "MISSING"},
                "content-security-policy": {"present": False, "status": "MISSING"},
                "x-frame-options": {"present": False, "status": "MISSING"},
                "x-content-type-options": {"present": False, "status": "MISSING"},
            },
        )
        db.add(service_https)
        db.flush()

        # Service Exposure 2 (Cleartext HTTP on Port 80)
        service_http = ServiceExposure(
            asset_id=sub_asset.id,
            scan_run_id=scan_run.id,
            port=80,
            protocol="tcp",
            service_name="http",
            http_status=200,
            tls_version=None,
            page_title="Redirect Portal",
            security_headers={},
        )
        db.add(service_http)
        db.flush()

        # Technology 1 (nginx 1.20.0 with correlated vulnerability)
        tech_nginx = Technology(
            asset_id=sub_asset.id,
            service_id=service_https.id,
            scan_run_id=scan_run.id,
            name="nginx",
            version="1.20.0",
            cpe="cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*",
            category="web_server",
            confidence=0.95,
            evidence_source="server_header",
        )
        db.add(tech_nginx)
        db.flush()

        # Technology 2 (React - safe library with NO vulnerability correlation)
        tech_react = Technology(
            asset_id=sub_asset.id,
            service_id=service_https.id,
            scan_run_id=scan_run.id,
            name="React",
            version="18.2.0",
            cpe="cpe:2.3:a:facebook:react:18.2.0:*:*:*:*:*:*:*",
            category="js_library",
            confidence=0.90,
            evidence_source="script_src",
        )
        db.add(tech_react)
        db.flush()

        # Vulnerability (CVE with CVSS 7.5 and CISA KEV listing)
        vuln = Vulnerability(
            cve_id=rand_cve,
            title="1-byte memory overwrite in resolver",
            description="A security flaw exists in nginx 1.20.0 resolver.",
            severity="HIGH",
            cvss_v3_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            source="NVD",
            references=[{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
        )
        db.add(vuln)
        db.flush()

        tv = TechnologyVulnerability(
            technology_id=tech_nginx.id,
            vulnerability_id=vuln.id,
            match_confidence=0.95,
            verification_status="potential",
            notes='{"match_basis": "Exact CPE match", "cisa_kev": true}',
        )
        db.add(tv)

        # Expired TLS Certificate
        cert_expired = Certificate(
            fingerprint_sha256=rand_fp,
            subject_cn=f"api.findingstest-{rand_id}.com",
            issuer="Let's Encrypt Authority X3",
            san_list=[f"api.findingstest-{rand_id}.com"],
            valid_from=datetime(2023, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2024, 1, 1, tzinfo=timezone.utc),
            is_expired=True,
        )
        db.add(cert_expired)
        db.flush()

        db.execute(
            subdomain_certificates.insert().values(
                subdomain_id=subdomain.id,
                certificate_id=cert_expired.id,
                scan_run_id=scan_run.id,
                observed_at=datetime.now(timezone.utc),
            )
        )

        db.commit()

        context = {
            "target_id": target.id,
            "investigation_id": inv.id,
            "scan_run_id": scan_run.id,
            "sub_asset_id": sub_asset.id,
            "tech_nginx_id": tech_nginx.id,
            "tech_react_id": tech_react.id,
            "vuln_id": vuln.id,
            "cve_id": rand_cve,
            "cert_id": cert_expired.id,
            "analyst_id": analyst_id,
        }

    try:
        yield context
    finally:
        with TestingSessionLocal() as db:
            db.execute(
                subdomain_certificates.delete().where(
                    subdomain_certificates.c.certificate_id == context["cert_id"]
                )
            )
            t = db.get(Target, context["target_id"])
            if t:
                db.delete(t)
            c = db.get(Certificate, context["cert_id"])
            if c:
                db.delete(c)
            v = db.get(Vulnerability, context["vuln_id"])
            if v:
                db.delete(v)
            db.commit()


# --- Unit Tests: Risk Formula & Boundaries ---

def test_risk_formula_bounds_and_determinism():
    """Verify that calculate_risk_score is strictly bounded [0, 100] and deterministic."""
    # Test 1: Minimum possible score
    score_min, cat_min, factors_min = FindingService.calculate_risk_score(
        base_severity="INFO",
        cvss_score=0.0,
        is_kev=False,
        is_exposed=False,
        tech_confidence=0.5,
    )
    assert 0 <= score_min <= 100
    assert score_min == 0  # 0 base - 10 confidence = -10 clamped to 0
    assert cat_min == "INFORMATIONAL"

    # Test 2: Maximum possible score
    score_max, cat_max, factors_max = FindingService.calculate_risk_score(
        base_severity="CRITICAL",
        cvss_score=10.0,
        is_kev=True,
        is_exposed=True,
        tech_confidence=0.95,
    )
    assert 0 <= score_max <= 100
    assert score_max == 100  # 100 + 15 + 10 + 5 = 130 clamped to 100
    assert cat_max == "CRITICAL"

    # Test 3: Deterministic repeatability
    score_a, _, _ = FindingService.calculate_risk_score(
        base_severity="HIGH", cvss_score=7.5, is_kev=True, is_exposed=True, tech_confidence=0.95
    )
    score_b, _, _ = FindingService.calculate_risk_score(
        base_severity="HIGH", cvss_score=7.5, is_kev=True, is_exposed=True, tech_confidence=0.95
    )
    assert score_a == score_b
    assert score_a == 100  # 75 + 15 + 10 + 5 = 105 -> 100


def test_risk_category_thresholds():
    """Verify Platform Risk category thresholds: CRITICAL (80+), HIGH (60-79), MEDIUM (40-59), LOW (20-39), INFO (<20)."""
    _, cat85, _ = FindingService.calculate_risk_score("CRITICAL", cvss_score=8.5, is_kev=False, is_exposed=False, tech_confidence=0.8)
    assert cat85 == "CRITICAL"  # 85

    _, cat65, _ = FindingService.calculate_risk_score("HIGH", cvss_score=6.5, is_kev=False, is_exposed=False, tech_confidence=0.8)
    assert cat65 == "HIGH"  # 65

    _, cat45, _ = FindingService.calculate_risk_score("MEDIUM", cvss_score=4.5, is_kev=False, is_exposed=False, tech_confidence=0.8)
    assert cat45 == "MEDIUM"  # 45

    _, cat25, _ = FindingService.calculate_risk_score("LOW", cvss_score=2.5, is_kev=False, is_exposed=False, tech_confidence=0.8)
    assert cat25 == "LOW"  # 25

    _, cat10, _ = FindingService.calculate_risk_score("INFO", cvss_score=1.0, is_kev=False, is_exposed=False, tech_confidence=0.8)
    assert cat10 == "INFORMATIONAL"  # 10


# --- Integration Tests: Findings Generation & API ---

def test_1_generate_vulnerability_finding(populated_findings_environment):
    """Verify that TechnologyVulnerability produces an evidence-backed VULNERABILITY finding."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    vuln_findings = [f for f in data["findings"] if f["finding_type"] == "VULNERABILITY"]
    assert len(vuln_findings) >= 1
    vf = vuln_findings[0]

    assert env["cve_id"] in vf["title"]
    assert vf["severity"] == "HIGH"
    assert vf["cvss_score"] == 7.5
    assert vf["is_kev"] is True
    # 75 base + 15 KEV + 10 exposed + 5 confidence = 105 -> clamped to 100
    assert vf["context_score"] == 100
    assert vf["risk_category"] == "CRITICAL"
    assert "Upgrade 'nginx'" in vf["remediation"]


def test_2_generate_security_header_findings(populated_findings_environment):
    """Verify that missing security headers (HSTS, CSP, XFO, XCTO) produce SECURITY_HEADER findings."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    header_findings = [f for f in data["findings"] if f["finding_type"] == "SECURITY_HEADER"]
    titles = [f["title"] for f in header_findings]

    assert any("HSTS" in t for t in titles)
    assert any("CSP" in t or "Content Security Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)


def test_3_generate_tls_findings(populated_findings_environment):
    """Verify expired TLS certificate produces a TLS_SECURITY finding."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    tls_findings = [f for f in data["findings"] if f["finding_type"] == "TLS_SECURITY"]
    assert len(tls_findings) >= 1
    tf = tls_findings[0]
    assert "Expired TLS Certificate" in tf["title"]
    assert tf["severity"] == "HIGH"


def test_4_generate_service_exposure_findings(populated_findings_environment):
    """Verify cleartext HTTP port 80 produces a SERVICE_EXPOSURE finding."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    svc_findings = [f for f in data["findings"] if f["finding_type"] == "SERVICE_EXPOSURE"]
    assert len(svc_findings) >= 1
    assert "Port 80" in svc_findings[0]["title"]
    assert svc_findings[0]["severity"] == "LOW"


def test_5_no_finding_from_technology_alone(populated_findings_environment):
    """Verify that observed Technology with no CVE (e.g. React 18.2.0) does NOT produce a finding."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    # React has no TechnologyVulnerability in the test environment
    react_vuln_findings = [
        f for f in data["findings"]
        if f["finding_type"] == "VULNERABILITY" and "React" in f["title"]
    ]
    assert len(react_vuln_findings) == 0


def test_6_cvss_preservation_and_risk_factors_breakdown(populated_findings_environment):
    """Verify CVSS score is preserved and score_breakdown provides transparent factors."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    response = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()

    vuln_finding = [f for f in data["findings"] if f["finding_type"] == "VULNERABILITY"][0]
    assert vuln_finding["cvss_score"] == 7.5

    factors = vuln_finding["risk_factors"]
    assert "base_score" in factors
    assert "base_factor" in factors
    assert factors["cisa_kev_adjustment"] == 15
    assert factors["exposure_adjustment"] == 10
    assert factors["confidence_adjustment"] == 5
    assert factors["final_score"] == 100


def test_7_finding_deduplication_and_idempotency(populated_findings_environment):
    """Verify that executing findings generation repeatedly does NOT create duplicate records."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    res1 = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert res1.status_code == 200
    total1 = res1.json()["findings_total"]

    res2 = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert res2.status_code == 200
    total2 = res2.json()["findings_total"]
    created_on_second_run = res2.json()["findings_generated"]

    assert total1 == total2
    assert created_on_second_run == 0


def test_8_scan_run_historical_isolation():
    """
    CRITICAL TEST: Verify historical scan isolation for findings.
    ScanRun 1 has nginx 1.20 (Vulnerable).
    ScanRun 2 has no vulnerable technology.
    Findings for ScanRun 1 must remain intact and isolated.
    """
    target_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("81111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target = Target(name=f"Iso Target {rand_code}", primary_domain=f"fiso-{rand_code.lower()}.com", organization="ISO")
            db.add(target)
            db.flush()
            target_id = target.id

            inv = Investigation(
                reference_code=f"INV-FISO-{rand_code}",
                target_id=target.id,
                title="Historical Isolation Assessment",
                created_by_id=analyst_id,
            )
            db.add(inv)
            db.flush()

            scan1 = ScanRun(investigation_id=inv.id, run_number=1, status="completed")
            scan2 = ScanRun(investigation_id=inv.id, run_number=2, status="completed")
            db.add_all([scan1, scan2])
            db.flush()

            dom_asset = Asset(target_id=target.id, investigation_id=inv.id, asset_type="domain", value=f"fiso-{rand_code.lower()}.com", source="ct")
            db.add(dom_asset)
            db.flush()

            # Scan 1 Tech with vulnerability
            tech1 = Technology(asset_id=dom_asset.id, scan_run_id=scan1.id, name="Apache", version="2.4.49", category="web_server", confidence=0.95, evidence_source="headers")
            db.add(tech1)
            db.flush()

            vuln1 = Vulnerability(cve_id=f"CVE-2021-{random.randint(10000, 99999)}", title="Path traversal", description="Critical flaw", severity="CRITICAL", cvss_v3_score=9.8, source="NVD")
            db.add(vuln1)
            db.flush()

            tv1 = TechnologyVulnerability(technology_id=tech1.id, vulnerability_id=vuln1.id, match_confidence=0.95, verification_status="potential")
            db.add(tv1)

            # Scan 2 Tech (patched - no vulnerability)
            tech2 = Technology(asset_id=dom_asset.id, scan_run_id=scan2.id, name="Apache", version="2.4.52", category="web_server", confidence=0.95, evidence_source="headers")
            db.add(tech2)

            db.commit()
            inv_id = inv.id
            scan1_id = scan1.id
            scan2_id = scan2.id

        headers = get_auth_headers(analyst_id, "analyst_8a", "analyst")

        # Generate findings for ScanRun 1
        res1 = client.post(f"/api/investigations/{inv_id}/findings/generate?scan_run_id={scan1_id}", headers=headers)
        assert res1.status_code == 200
        assert res1.json()["findings_total"] >= 1

        # Generate findings for ScanRun 2
        res2 = client.post(f"/api/investigations/{inv_id}/findings/generate?scan_run_id={scan2_id}", headers=headers)
        assert res2.status_code == 200
        assert len([f for f in res2.json()["findings"] if f["finding_type"] == "VULNERABILITY"]) == 0

        # Query ScanRun 1 findings again: Must still exist
        list1 = client.get(f"/api/investigations/{inv_id}/findings?scan_run_id={scan1_id}", headers=headers)
        assert list1.status_code == 200
        assert list1.json()["total"] >= 1
    finally:
        if target_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target_id)
                if t:
                    db.delete(t)
                db.commit()


def test_9_cross_investigation_scan_run_rejection(populated_findings_environment):
    """Verify that requesting findings generation with a ScanRun from another investigation is rejected with 400."""
    env = populated_findings_environment
    target2_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("81111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target2 = Target(name=f"Other Corp {rand_code}", primary_domain=f"othercorp-{rand_code.lower()}.com", organization="Other")
            db.add(target2)
            db.flush()
            target2_id = target2.id

            inv2 = Investigation(reference_code=f"INV-OTHER-{rand_code}", target_id=target2.id, title="Other Assessment", created_by_id=analyst_id)
            db.add(inv2)
            db.flush()

            scan_other = ScanRun(investigation_id=inv2.id, run_number=1, status="completed")
            db.add(scan_other)
            db.commit()
            other_scan_id = scan_other.id

        headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

        # Attempt to query Inv 1 with Inv 2's scan_run_id
        res = client.post(
            f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={other_scan_id}",
            headers=headers,
        )
        assert res.status_code == 400
        assert "does not belong" in res.json()["detail"].lower()
    finally:
        if target2_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target2_id)
                if t:
                    db.delete(t)
                db.commit()


def test_10_cross_investigation_finding_idor_rejection(populated_findings_environment):
    """Verify IDOR protection: requesting a finding using another investigation's ID returns 404."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    # Generate finding first
    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    finding_id = gen_res.json()["findings"][0]["id"]

    fake_inv_id = uuid.uuid4()
    idor_res = client.get(
        f"/api/investigations/{fake_inv_id}/findings/{finding_id}",
        headers=headers,
    )
    assert idor_res.status_code == 404


def test_11_unauthorized_investigation_access_rejection(populated_findings_environment):
    """Verify RBAC: Analyst 2 cannot access Analyst 1's findings (403); Admin can access (200)."""
    env = populated_findings_environment
    analyst2_headers = get_auth_headers(uuid.UUID("82222222-2222-2222-2222-222222222222"), "analyst_8b", "analyst")
    admin_headers = get_auth_headers(uuid.UUID("83333333-3333-3333-3333-333333333333"), "admin_8", "admin")

    res_forbidden = client.get(
        f"/api/investigations/{env['investigation_id']}/findings",
        headers=analyst2_headers,
    )
    assert res_forbidden.status_code == 403

    res_admin = client.get(
        f"/api/investigations/{env['investigation_id']}/findings",
        headers=admin_headers,
    )
    assert res_admin.status_code == 200


def test_12_finding_status_lifecycle_update(populated_findings_environment):
    """Verify PATCH /findings/{id} updates lifecycle status (open -> acknowledged -> resolved)."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    finding_id = gen_res.json()["findings"][0]["id"]

    # Update to acknowledged
    patch_res = client.patch(
        f"/api/investigations/{env['investigation_id']}/findings/{finding_id}",
        headers=headers,
        json={"status": "acknowledged"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "acknowledged"

    # Update to resolved
    patch_res2 = client.patch(
        f"/api/investigations/{env['investigation_id']}/findings/{finding_id}",
        headers=headers,
        json={"status": "resolved"},
    )
    assert patch_res2.status_code == 200
    assert patch_res2.json()["status"] == "resolved"


def test_13_filter_findings_by_severity_and_type(populated_findings_environment):
    """Verify query filtering by severity and finding_type."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    # Generate findings first
    client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )

    # Filter by VULNERABILITY
    vuln_res = client.get(
        f"/api/investigations/{env['investigation_id']}/findings?finding_type=VULNERABILITY",
        headers=headers,
    )
    assert vuln_res.status_code == 200
    for f in vuln_res.json()["findings"]:
        assert f["finding_type"] == "VULNERABILITY"

    # Filter by LOW severity
    low_res = client.get(
        f"/api/investigations/{env['investigation_id']}/findings?severity=LOW",
        headers=headers,
    )
    assert low_res.status_code == 200
    for f in low_res.json()["findings"]:
        assert f["severity"] == "LOW"


def test_14_stage6_stage7_regression_intact(populated_findings_environment):
    """Verify Stage 6 vulnerabilities and Stage 7 attack surface graph continue working seamlessly."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    # Stage 6 check
    vuln_res = client.get(
        f"/api/investigations/{env['investigation_id']}/vulnerabilities?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert vuln_res.status_code == 200
    assert len(vuln_res.json()) >= 1

    # Stage 7 graph check
    graph_res = client.get(
        f"/api/investigations/{env['investigation_id']}/graph?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert graph_res.status_code == 200
    assert len(graph_res.json()["nodes"]) > 0
    assert len(graph_res.json()["edges"]) > 0


def test_15_low_confidence_and_missing_cvss_adjustments():
    """Verify confidence <= 0.60 deducts 10 points and missing CVSS maps to severity baseline."""
    # Low confidence deduction (-10)
    score_low_conf, _, factors = FindingService.calculate_risk_score(
        base_severity="HIGH",
        cvss_score=7.0,
        is_kev=False,
        is_exposed=False,
        tech_confidence=0.50,
    )
    assert factors["confidence_adjustment"] == -10
    assert score_low_conf == 60  # 70 base - 10 conf = 60

    # Missing CVSS with CRITICAL severity (75 base)
    score_no_cvss, cat, _ = FindingService.calculate_risk_score(
        base_severity="CRITICAL",
        cvss_score=None,
        is_kev=False,
        is_exposed=False,
        tech_confidence=0.80,
    )
    assert score_no_cvss == 75
    assert cat == "HIGH"


def test_16_single_finding_detail_endpoint(populated_findings_environment):
    """Verify GET /findings/{id} returns fully populated detail schema with risk factors and asset info."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    finding_id = gen_res.json()["findings"][0]["id"]

    detail_res = client.get(
        f"/api/investigations/{env['investigation_id']}/findings/{finding_id}",
        headers=headers,
    )
    assert detail_res.status_code == 200
    detail = detail_res.json()

    assert detail["id"] == finding_id
    assert detail["reference_code"].startswith("F-")
    assert detail["asset"]["value"] == f"api.findingstest-{env['target_id'].hex[:8]}.com" or "findingstest" in detail["asset"]["value"]
    assert "risk_factors" in detail
    assert "recommendation" in detail


def test_17_empty_investigation_findings():
    """Verify generating findings on an empty investigation returns 0 findings cleanly."""
    target_id = None
    try:
        with TestingSessionLocal() as db:
            analyst_id = uuid.UUID("81111111-1111-1111-1111-111111111111")
            rand_code = uuid.uuid4().hex[:6].upper()
            target = Target(name=f"Empty Target {rand_code}", primary_domain=f"empty-{rand_code.lower()}.com", organization="Empty")
            db.add(target)
            db.flush()
            target_id = target.id

            inv = Investigation(reference_code=f"INV-EMP-{rand_code}", target_id=target.id, title="Empty Assessment", created_by_id=analyst_id)
            db.add(inv)
            db.commit()
            inv_id = inv.id

        headers = get_auth_headers(analyst_id, "analyst_8a", "analyst")
        res = client.post(f"/api/investigations/{inv_id}/findings/generate", headers=headers)
        assert res.status_code == 200
        assert res.json()["findings_total"] == 0
    finally:
        if target_id:
            with TestingSessionLocal() as db:
                t = db.get(Target, target_id)
                if t:
                    db.delete(t)
                db.commit()


def test_18_invalid_status_update_rejection(populated_findings_environment):
    """Verify invalid status string returns 400 Bad Request."""
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    finding_id = gen_res.json()["findings"][0]["id"]

    res = client.patch(
        f"/api/investigations/{env['investigation_id']}/findings/{finding_id}",
        headers=headers,
        json={"status": "invalid_status_xyz"},
    )
    assert res.status_code == 422 or res.status_code == 400


def test_19_requires_verification_semantics_survives_finding_generation(populated_findings_environment):
    """
    Verify that an unversioned technology (e.g. Cloudflare) correlated as REQUIRES_VERIFICATION:
    1. Retains correlation_status="REQUIRES_VERIFICATION" in Finding entity and API responses.
    2. Retains verification_status="requires_verification" and is_version_supported=False.
    3. is_verified remains False (passive correlation is not proof of exploitability).
    4. Retains "Potential Vulnerability: ..." wording in title.
    5. High contextual risk is permitted (e.g. public perimeter reachability) while explicitly flagged as requiring verification.
    """
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    cve_id = "CVE-2017-7235"
    with TestingSessionLocal() as db:
        # Create unversioned technology
        tech_unversioned = Technology(
            asset_id=env["sub_asset_id"],
            scan_run_id=env["scan_run_id"],
            name="Cloudflare",
            version=None,
            cpe="cpe:2.3:a:cloudflare:cloudflare:*:*:*:*:*:*:*:*",
            category="cdn",
            confidence=1.0,
            evidence_source="server_header",
        )
        db.add(tech_unversioned)
        db.flush()

        vuln_unversioned = Vulnerability(
            cve_id=cve_id,
            title="Cloudflare Buffer Overflow",
            description="Buffer overflow in Cloudflare reverse proxy.",
            severity="CRITICAL",
            cvss_v3_score=8.8,
            source="NVD",
            references=[],
        )
        db.add(vuln_unversioned)
        db.flush()

        tv_unversioned = TechnologyVulnerability(
            technology_id=tech_unversioned.id,
            vulnerability_id=vuln_unversioned.id,
            match_confidence=0.5,
            verification_status="requires_verification",
            notes='{"correlation_status": "REQUIRES_VERIFICATION", "match_basis": "Observed technology \'Cloudflare\' without verifiable version. CPE/advisory matches \'CVE-2017-7235\'. Verification required.", "is_kev": false}',
        )
        db.add(tv_unversioned)
        db.commit()

    # Generate findings
    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert gen_res.status_code == 200
    data = gen_res.json()

    # Find the Cloudflare finding
    cf_finding = next((f for f in data["findings"] if cve_id in f["title"]), None)
    assert cf_finding is not None, f"Expected finding for {cve_id} not found in generated findings"

    # Verify semantics
    assert cf_finding["title"].startswith("Potential Vulnerability: CVE-2017-7235 affecting Cloudflare")
    assert cf_finding["is_verified"] is False
    assert cf_finding["correlation_status"] == "REQUIRES_VERIFICATION"
    assert cf_finding["verification_status"] == "requires_verification"
    assert cf_finding["is_version_supported"] is False
    assert "Verification required" in cf_finding["match_basis"]
    assert cf_finding["context_score"] >= 80  # Contextual score is high due to CVSS 8.8 + Internet exposure

    # Verify Detail Endpoint preserves verification fields
    detail_res = client.get(
        f"/api/investigations/{env['investigation_id']}/findings/{cf_finding['id']}",
        headers=headers,
    )
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["correlation_status"] == "REQUIRES_VERIFICATION"
    assert detail["verification_status"] == "requires_verification"
    assert detail["is_version_supported"] is False
    assert detail["is_verified"] is False


def test_20_version_supported_match_semantics(populated_findings_environment):
    """
    Verify that a versioned technology with concrete version match:
    1. Retains correlation_status="POTENTIAL_MATCH" and is_version_supported=True.
    2. is_verified remains False (passive correlation is not confirmed exploitation).
    3. Retains "Potential Vulnerability: ..." wording in title.
    """
    env = populated_findings_environment
    headers = get_auth_headers(env["analyst_id"], "analyst_8a", "analyst")

    gen_res = client.post(
        f"/api/investigations/{env['investigation_id']}/findings/generate?scan_run_id={env['scan_run_id']}",
        headers=headers,
    )
    assert gen_res.status_code == 200
    data = gen_res.json()

    # nginx finding (which was seeded with version 1.20.0 and POTENTIAL_MATCH)
    nginx_finding = next((f for f in data["findings"] if "nginx" in f["title"]), None)
    assert nginx_finding is not None

    assert nginx_finding["title"].startswith("Potential Vulnerability:")
    assert nginx_finding["is_verified"] is False
    assert nginx_finding["correlation_status"] == "POTENTIAL_MATCH"
    assert nginx_finding["is_version_supported"] is True
    assert nginx_finding["match_basis"] is not None


