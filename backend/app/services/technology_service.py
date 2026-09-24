"""Technology fingerprinting signature engine and detection service."""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from backend.app.services.http_service import HTTPProbeObservation
from backend.app.core.logging import logger


@dataclass
class DetectedTechnology:
    """Structure representing a verified technology detection with concrete evidence."""
    name: str
    category: str  # web_server, framework, cms, js_framework, frontend_library, cdn_proxy, programming_language
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: float = 0.9
    evidence: str = ""
    evidence_source: str = "headers"  # headers, meta_generator, html_body, cookie, script_src


@dataclass
class HeaderRule:
    """Header pattern matching rule."""
    header: str
    pattern: Optional[re.Pattern] = None
    exact_value: Optional[str] = None
    version_regex: Optional[re.Pattern] = None
    evidence_template: str = "Header: {header}={value}"
    confidence: float = 0.95


@dataclass
class CookieRule:
    """Cookie presence or pattern matching rule."""
    cookie_name: str
    pattern: Optional[re.Pattern] = None
    version_regex: Optional[re.Pattern] = None
    evidence_template: str = "Cookie: {cookie}"
    confidence: float = 0.9


@dataclass
class HTMLRule:
    """HTML body or meta-tag pattern matching rule."""
    pattern: re.Pattern
    version_regex: Optional[re.Pattern] = None
    evidence_source: str = "html_body"  # html_body, meta_generator, script_src
    evidence_desc: str = "HTML marker: {matched}"
    confidence: float = 0.85


@dataclass
class TechnologySignature:
    """Structured signature specification for detecting a web technology."""
    name: str
    category: str
    cpe_template: Optional[str] = None
    header_rules: List[HeaderRule] = field(default_factory=list)
    cookie_rules: List[CookieRule] = field(default_factory=list)
    html_rules: List[HTMLRule] = field(default_factory=list)


class TechnologyFingerprintProvider:
    """
    Extensible technology signature provider.
    Maintains a curated catalog of technology signatures across web servers, CMS,
    frameworks, JS libraries, CDN proxies, and languages.
    """

    def __init__(self, signatures: Optional[List[TechnologySignature]] = None):
        self._signatures = signatures if signatures is not None else self._build_default_signatures()

    @staticmethod
    def _build_default_signatures() -> List[TechnologySignature]:
        """Curated signature database with explicit evidence capture and version regexes."""
        return [
            # --- WEB SERVERS ---
            TechnologySignature(
                name="nginx",
                category="web_server",
                cpe_template="cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bnginx(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bnginx/([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="Apache",
                category="web_server",
                cpe_template="cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bApache(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bApache/([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="Microsoft-IIS",
                category="web_server",
                cpe_template="cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bMicrosoft-IIS(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bMicrosoft-IIS/([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="Caddy",
                category="web_server",
                cpe_template="cpe:2.3:a:caddyserver:caddy:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bCaddy(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bCaddy/v?([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="LiteSpeed",
                category="web_server",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bLiteSpeed", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="OpenResty",
                category="web_server",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bopenresty(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bopenresty/([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),

            # --- CDN / REVERSE PROXIES ---
            TechnologySignature(
                name="Cloudflare",
                category="cdn_proxy",
                header_rules=[
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"^cloudflare$", re.IGNORECASE),
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="cf-ray",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: CF-Ray observed",
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="cf-cache-status",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: CF-Cache-Status observed",
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Varnish",
                category="cdn_proxy",
                header_rules=[
                    HeaderRule(
                        header="x-varnish",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: X-Varnish observed",
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="via",
                        pattern=re.compile(r"\bvarnish\b", re.IGNORECASE),
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Amazon CloudFront",
                category="cdn_proxy",
                header_rules=[
                    HeaderRule(
                        header="x-amz-cf-id",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: X-Amz-Cf-Id observed",
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="via",
                        pattern=re.compile(r"\bCloudFront\b", re.IGNORECASE),
                        confidence=0.95,
                    ),
                ],
            ),

            # --- CMS PLATFORMS ---
            TechnologySignature(
                name="WordPress",
                category="cms",
                cpe_template="cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="x-powered-by",
                        pattern=re.compile(r"WordPress", re.IGNORECASE),
                        confidence=0.95,
                    ),
                ],
                cookie_rules=[
                    CookieRule(
                        cookie_name="wordpress_",
                        pattern=re.compile(r"^wordpress_"),
                        evidence_template="Cookie: WordPress session/auth cookie observed",
                        confidence=0.95,
                    ),
                    CookieRule(
                        cookie_name="wp-settings",
                        pattern=re.compile(r"^wp-settings"),
                        evidence_template="Cookie: wp-settings observed",
                        confidence=0.95,
                    ),
                ],
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)["\']', re.IGNORECASE),
                        version_regex=re.compile(r'content=["\']WordPress\s*([\d.]+)["\']', re.IGNORECASE),
                        evidence_source="meta_generator",
                        evidence_desc="Meta generator: WordPress {version}",
                        confidence=1.0,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/wp-content/(?:themes|plugins)/', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: /wp-content/ asset path",
                        confidence=0.9,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/wp-includes/js/', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: /wp-includes/ script path",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="Drupal",
                category="cms",
                cpe_template="cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
                header_rules=[
                    HeaderRule(
                        header="x-drupal-cache",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: X-Drupal-Cache observed",
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="x-generator",
                        pattern=re.compile(r"Drupal\s*([\d.]*)", re.IGNORECASE),
                        version_regex=re.compile(r"Drupal\s*([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]*)["\']', re.IGNORECASE),
                        version_regex=re.compile(r'content=["\']Drupal\s*([\d.]+)["\']', re.IGNORECASE),
                        evidence_source="meta_generator",
                        evidence_desc="Meta generator: Drupal {version}",
                        confidence=1.0,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'sites/all/(?:themes|modules)/', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: sites/all/ Drupal structure",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="Joomla",
                category="cms",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s*-?\s*([\d.]*)["\']', re.IGNORECASE),
                        version_regex=re.compile(r'content=["\']Joomla!\s*-?\s*([\d.]+)["\']', re.IGNORECASE),
                        evidence_source="meta_generator",
                        evidence_desc="Meta generator: Joomla! {version}",
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="Shopify",
                category="cms",
                header_rules=[
                    HeaderRule(
                        header="x-shopify-stage",
                        pattern=re.compile(r".+"),
                        evidence_template="Header: X-Shopify-Stage observed",
                        confidence=1.0,
                    ),
                ],
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'cdn\.shopify\.com/', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: cdn.shopify.com assets",
                        confidence=0.95,
                    ),
                ],
            ),

            # --- WEB FRAMEWORKS & RUNTIMES ---
            TechnologySignature(
                name="PHP",
                category="programming_language",
                header_rules=[
                    HeaderRule(
                        header="x-powered-by",
                        pattern=re.compile(r"\bPHP(?:/([\d.]+))?", re.IGNORECASE),
                        version_regex=re.compile(r"\bPHP/([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="server",
                        pattern=re.compile(r"\bPHP/([\d.]+)", re.IGNORECASE),
                        version_regex=re.compile(r"\bPHP/([\d.]+)", re.IGNORECASE),
                        confidence=0.95,
                    ),
                ],
                cookie_rules=[
                    CookieRule(
                        cookie_name="PHPSESSID",
                        evidence_template="Cookie: PHPSESSID session identifier observed",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="ASP.NET",
                category="framework",
                header_rules=[
                    HeaderRule(
                        header="x-powered-by",
                        pattern=re.compile(r"ASP\.NET", re.IGNORECASE),
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="x-aspnet-version",
                        pattern=re.compile(r"([\d.]+)", re.IGNORECASE),
                        version_regex=re.compile(r"([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                    HeaderRule(
                        header="x-aspnetmvc-version",
                        pattern=re.compile(r"([\d.]+)", re.IGNORECASE),
                        version_regex=re.compile(r"([\d.]+)", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
                cookie_rules=[
                    CookieRule(
                        cookie_name="ASP.NET_SessionId",
                        evidence_template="Cookie: ASP.NET_SessionId observed",
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Express",
                category="framework",
                header_rules=[
                    HeaderRule(
                        header="x-powered-by",
                        pattern=re.compile(r"^Express$", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
            ),
            TechnologySignature(
                name="Django",
                category="framework",
                cookie_rules=[
                    CookieRule(
                        cookie_name="csrftoken",
                        evidence_template="Cookie: csrftoken (Django format) observed",
                        confidence=0.8,
                    ),
                    CookieRule(
                        cookie_name="django_session",
                        evidence_template="Cookie: django_session observed",
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Laravel",
                category="framework",
                cookie_rules=[
                    CookieRule(
                        cookie_name="laravel_session",
                        evidence_template="Cookie: laravel_session observed",
                        confidence=0.95,
                    ),
                ],
            ),

            # --- JAVASCRIPT FRAMEWORKS & LIBRARIES ---
            TechnologySignature(
                name="React",
                category="js_framework",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'data-reactroot=""|data-reactid=', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: React root attributes (data-reactroot)",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'react(?:\.production)?(?:\.min)?\.js', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: React runtime script loaded",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="Next.js",
                category="framework",
                header_rules=[
                    HeaderRule(
                        header="x-powered-by",
                        pattern=re.compile(r"Next\.js", re.IGNORECASE),
                        confidence=1.0,
                    ),
                ],
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'id=["\']__next["\']', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Next.js root element (#__next)",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/_next/static/', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: Next.js /_next/static/ assets",
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Vue.js",
                category="js_framework",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'data-v-[a-f0-9]{6,8}', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Vue.js scoped CSS attribute (data-v-*)",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'vue(?:\.runtime)?(?:\.min)?\.js', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: Vue.js script tag",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="Nuxt.js",
                category="framework",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'id=["\']__nuxt["\']', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Nuxt root element (#__nuxt)",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/_nuxt/', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: Nuxt /_nuxt/ assets",
                        confidence=0.95,
                    ),
                ],
            ),
            TechnologySignature(
                name="Angular",
                category="js_framework",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'ng-version=["\']([\d.]+)["\']', re.IGNORECASE),
                        version_regex=re.compile(r'ng-version=["\']([\d.]+)["\']', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Angular ng-version={version}",
                        confidence=1.0,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'ng-app=|ng-controller=', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: AngularJS directive (ng-app)",
                        confidence=0.9,
                    ),
                ],
            ),
            TechnologySignature(
                name="jQuery",
                category="frontend_library",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.IGNORECASE),
                        version_regex=re.compile(r'jquery[.-]([\d.]+)(?:\.min)?\.js', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: jQuery {version} script loaded",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/\*! jQuery v([\d.]+)', re.IGNORECASE),
                        version_regex=re.compile(r'/\*! jQuery v([\d.]+)', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: jQuery v{version} banner",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'jquery(?:\.min)?\.js', re.IGNORECASE),
                        evidence_source="script_src",
                        evidence_desc="Script marker: jQuery library loaded",
                        confidence=0.85,
                    ),
                ],
            ),
            TechnologySignature(
                name="Bootstrap",
                category="frontend_library",
                html_rules=[
                    HTMLRule(
                        pattern=re.compile(r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)', re.IGNORECASE),
                        version_regex=re.compile(r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:css|js)', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Bootstrap {version} CSS/JS",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'/\*![\s\n]*Bootstrap v([\d.]+)', re.IGNORECASE),
                        version_regex=re.compile(r'/\*![\s\n]*Bootstrap v([\d.]+)', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Bootstrap v{version} banner",
                        confidence=0.95,
                    ),
                    HTMLRule(
                        pattern=re.compile(r'bootstrap(?:\.min)?\.(?:css|js)', re.IGNORECASE),
                        evidence_source="html_body",
                        evidence_desc="HTML marker: Bootstrap CSS/JS bundle",
                        confidence=0.85,
                    ),
                ],
            ),
        ]

    def detect(self, http_observation: HTTPProbeObservation) -> List[DetectedTechnology]:
        """
        Analyze an HTTP probe observation against active signatures.
        
        Returns a deduplicated list of detected technologies with concrete evidence.
        """
        if not http_observation.is_reachable:
            return []

        detections_by_name: Dict[str, DetectedTechnology] = {}
        headers_lower = http_observation.headers
        cookies = http_observation.cookies
        body = http_observation.body_snippet

        for sig in self._signatures:
            detected_version: Optional[str] = None
            evidence_str: Optional[str] = None
            evidence_src: str = "headers"
            max_conf: float = 0.0

            # 1. Evaluate Header Rules
            for h_rule in sig.header_rules:
                h_name = h_rule.header.lower()
                h_val = headers_lower.get(h_name)
                if not h_val:
                    continue

                matched = False
                if h_rule.exact_value and h_rule.exact_value.lower() == h_val.lower():
                    matched = True
                elif h_rule.pattern:
                    match_res = h_rule.pattern.search(h_val)
                    if match_res:
                        matched = True
                        if h_rule.version_regex:
                            v_match = h_rule.version_regex.search(h_val)
                            if v_match and v_match.group(1):
                                detected_version = v_match.group(1).strip()
                        elif match_res.groups() and match_res.group(1):
                            detected_version = match_res.group(1).strip()

                if matched:
                    max_conf = max(max_conf, h_rule.confidence)
                    evidence_src = "headers"
                    evidence_str = h_rule.evidence_template.format(
                        header=h_rule.header, value=h_val
                    )
                    break

            # 2. Evaluate Cookie Rules
            if not evidence_str:
                for c_rule in sig.cookie_rules:
                    for cookie_k, cookie_v in cookies.items():
                        matched = False
                        if c_rule.cookie_name == cookie_k:
                            matched = True
                        elif c_rule.pattern and c_rule.pattern.search(cookie_k):
                            matched = True

                        if matched:
                            max_conf = max(max_conf, c_rule.confidence)
                            evidence_src = "cookie"
                            evidence_str = c_rule.evidence_template.format(
                                cookie=cookie_k, value=cookie_v
                            )
                            if c_rule.version_regex and cookie_v:
                                v_m = c_rule.version_regex.search(cookie_v)
                                if v_m and v_m.group(1):
                                    detected_version = v_m.group(1).strip()
                            break
                    if evidence_str:
                        break

            # 3. Evaluate HTML Rules
            if body:
                for html_rule in sig.html_rules:
                    h_match = html_rule.pattern.search(body)
                    if h_match:
                        rule_version = None
                        if html_rule.version_regex:
                            v_m = html_rule.version_regex.search(body)
                            if v_m and v_m.group(1):
                                rule_version = v_m.group(1).strip()
                        elif h_match.groups() and h_match.group(1):
                            rule_version = h_match.group(1).strip()

                        if rule_version:
                            detected_version = rule_version

                        max_conf = max(max_conf, html_rule.confidence)
                        evidence_src = html_rule.evidence_source
                        matched_snippet = h_match.group(0)[:60]
                        evidence_str = html_rule.evidence_desc.format(
                            matched=matched_snippet,
                            version=detected_version or "",
                        ).replace("  ", " ").strip()
                        break

            # If technology was detected
            if evidence_str:
                # Build CPE if version is available and template exists
                cpe_str = None
                if detected_version and sig.cpe_template:
                    cpe_str = sig.cpe_template.format(version=detected_version)

                # Ensure version is clean (only digits and dots, no extra words)
                if detected_version:
                    cleaned_v = detected_version.strip().rstrip(".")
                    # Ensure version has at least one digit
                    if any(ch.isdigit() for ch in cleaned_v):
                        detected_version = cleaned_v
                    else:
                        detected_version = None

                detection = DetectedTechnology(
                    name=sig.name,
                    category=sig.category,
                    version=detected_version,
                    cpe=cpe_str,
                    confidence=max_conf,
                    evidence=evidence_str[:200],
                    evidence_source=f"{evidence_src} ({evidence_str})"[:100],
                )

                # Deduplicate by technology name
                if sig.name not in detections_by_name:
                    detections_by_name[sig.name] = detection
                else:
                    existing = detections_by_name[sig.name]
                    # Upgrade version or confidence if new detection has better version
                    if not existing.version and detection.version:
                        existing.version = detection.version
                        existing.cpe = detection.cpe
                        existing.evidence = detection.evidence
                        existing.evidence_source = detection.evidence_source
                    existing.confidence = max(existing.confidence, detection.confidence)

        return list(detections_by_name.values())


class TechnologyService:
    """Service facade coordinating technology detection on HTTP observations."""

    def __init__(self, provider: Optional[TechnologyFingerprintProvider] = None):
        self._provider = provider or TechnologyFingerprintProvider()

    def fingerprint_http_observation(
        self, http_observation: HTTPProbeObservation
    ) -> List[DetectedTechnology]:
        """Fingerprint technologies present on an observed HTTP endpoint."""
        return self._provider.detect(http_observation)
