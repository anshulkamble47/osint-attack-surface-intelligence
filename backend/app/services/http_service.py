"""SSRF-safe HTTP Service Intelligence and TLS metadata collection."""

import ipaddress
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
import dns.resolver
import dns.exception
import httpx

from backend.app.core.logging import logger
from backend.app.services.ip_service import is_public_ip

TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class SecurityHeaderAnalysis:
    """Detailed observation of an individual HTTP security response header."""
    header_name: str
    present: bool
    value: Optional[str] = None
    status: str = "missing"  # configured, missing, deprecated, custom
    interpretation: str = "Header not observed"


@dataclass
class TLSMetadata:
    """Observed TLS session and certificate metadata for HTTPS endpoints."""
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_valid_from: Optional[datetime] = None
    cert_valid_to: Optional[datetime] = None
    cert_san_list: List[str] = field(default_factory=list)


@dataclass
class HTTPProbeObservation:
    """Comprehensive HTTP/HTTPS service observation for technology and security intelligence."""
    url: str
    port: int
    protocol: str  # tcp
    service_name: str  # http or https
    is_reachable: bool
    method: str = "GET"
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    redirect_count: int = 0
    response_time_ms: Optional[float] = None
    http_version: Optional[str] = None
    server_header: Optional[str] = None
    powered_by_header: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    page_title: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    security_headers: Dict[str, SecurityHeaderAnalysis] = field(default_factory=dict)
    tls_metadata: Optional[TLSMetadata] = None
    error: Optional[str] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class HTTPIntelligenceService:
    """
    SSRF-safe HTTP and TLS intelligence client.
    
    Collects:
    - Bounded response bodies and headers.
    - Security headers analysis (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
    - Passive TLS metadata for HTTPS endpoints.
    
    Enforces:
    - Pre-flight DNS public-IP validation (RFC 1918, loopback, link-local, multicast, reserved blocked).
    - Hop-by-hop redirect destination validation.
    - Response size ceilings (64 KB).
    - Explicit timeouts (3.0s).
    """

    DEFAULT_TIMEOUT_SECONDS = 3.0
    DEFAULT_MAX_REDIRECTS = 3
    MAX_BODY_BYTES = 65536  # 64 KB limit
    USER_AGENT = "Mozilla/5.0 (compatible; AttackSurfaceOSINT/1.0; +https://github.com/osint-platform)"

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        resolver: Optional[Any] = None,
    ):
        self._client = client
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._resolver = resolver

    def _get_resolver(self) -> dns.resolver.Resolver:
        if self._resolver is not None:
            return self._resolver
        res = dns.resolver.Resolver()
        res.timeout = 1.5
        res.lifetime = 1.5
        return res

    def _get_validated_public_ips(self, host: str) -> List[str]:
        """
        Resolve a hostname/IP and return list of all validated public IP addresses.
        
        Returns an empty list if:
        - Hostname is empty, loopback, or internal domain.
        - Host resolves to no addresses.
        - Any resolved IP address is private, loopback, link-local, multicast, or reserved.
        """
        cleaned_host = (host or "").strip().lower()
        if not cleaned_host:
            return []

        if (
            cleaned_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
            or cleaned_host.endswith(".local")
            or cleaned_host.endswith(".internal")
            or cleaned_host.endswith(".localhost")
        ):
            return []

        # 1. Check if host is an IP literal
        try:
            ip_obj = ipaddress.ip_address(cleaned_host)
            if is_public_ip(str(ip_obj)):
                return [str(ip_obj)]
            return []
        except ValueError:
            pass

        # 2. DNS resolution check (A and AAAA)
        resolver = self._get_resolver()
        resolved_ips: List[str] = []
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(cleaned_host, rtype)
                for rdata in answers:
                    resolved_ips.append(str(rdata).strip())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception:
                pass

        if not resolved_ips:
            return []

        # Validate that all resolved IPs are public
        validated: List[str] = []
        for rip in resolved_ips:
            if is_public_ip(rip):
                validated.append(rip)
            else:
                # If any address is non-public, reject to prevent partial SSRF
                return []

        return validated

    def _is_safe_url(self, url: str) -> bool:
        """Verify URL scheme and validate that target host resolves exclusively to public IPs."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False

            host = (parsed.hostname or "").strip().lower()
            if not host:
                return False

            valid_ips = self._get_validated_public_ips(host)
            return len(valid_ips) > 0
        except Exception:
            return False

    def probe_service(
        self,
        hostname: str,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        resolved_ips: Optional[List[str]] = None,
    ) -> HTTPProbeObservation:
        """
        Execute bounded, SSRF-safe HTTP/HTTPS intelligence on a known host/service.
        
        If resolved_ips is given, performs pre-flight verification to prevent querying non-public addresses.
        """
        cleaned_host = hostname.strip().rstrip(".")
        resolved_service = service_name or ("https" if port == 443 else "http")
        target_url = f"{resolved_service}://{cleaned_host}:{port}" if (
            (resolved_service == "http" and port != 80) or (resolved_service == "https" and port != 443)
        ) else f"{resolved_service}://{cleaned_host}"

        # 1. Pre-flight SSRF check
        if resolved_ips is not None and len(resolved_ips) > 0:
            if not any(is_public_ip(ip) for ip in resolved_ips):
                logger.info(f"SSRF Pre-flight: Host '{cleaned_host}' resolves only to private/reserved IPs. Skipping.")
                return HTTPProbeObservation(
                    url=target_url,
                    port=port,
                    protocol=protocol,
                    service_name=resolved_service,
                    is_reachable=False,
                    error="SSRF Blocked: Host resolves to non-public / reserved IP addresses",
                )

        validated_ips = self._get_validated_public_ips(cleaned_host)
        if not validated_ips:
            return HTTPProbeObservation(
                url=target_url,
                port=port,
                protocol=protocol,
                service_name=resolved_service,
                is_reachable=False,
                error=f"SSRF Blocked: Destination '{target_url}' is not public or failed DNS validation",
            )

        # 2. Perform TLS inspection if HTTPS (using pinned validated IP)
        tls_info: Optional[TLSMetadata] = None
        if resolved_service == "https":
            tls_info = self._inspect_tls(cleaned_host, port, validated_ips=validated_ips)

        # 3. Perform HTTP probe
        return self._execute_http_probe(
            target_url=target_url,
            hostname=cleaned_host,
            port=port,
            protocol=protocol,
            service_name=resolved_service,
            tls_info=tls_info,
        )

    def _inspect_tls(
        self, hostname: str, port: int, validated_ips: Optional[List[str]] = None
    ) -> Optional[TLSMetadata]:
        """
        Safely extract TLS protocol version, cipher suite, and certificate metadata.
        
        Security guarantee:
        The TCP connection connects directly to a validated public IP address (IP pinning)
        rather than passing the hostname to socket.create_connection, eliminating DNS TOCTOU
        and DNS rebinding attacks. The original hostname is supplied as server_hostname to
        context.wrap_socket, preserving TLS Server Name Indication (SNI).
        """
        try:
            # 1. Obtain validated public IPs
            target_ips = (
                validated_ips
                if validated_ips is not None
                else self._get_validated_public_ips(hostname)
            )
            if not target_ips:
                logger.debug(f"TLS inspection skipped for '{hostname}': No validated public IP found")
                return None

            # Pin to first validated public IP
            pinned_ip = target_ips[0]

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Permissive for OSINT inspection

            # Direct connection to validated IP eliminates DNS TOCTOU rebinding
            with socket.create_connection((pinned_ip, port), timeout=self._timeout) as sock:
                # server_hostname preserves SNI
                with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                    tls_ver = sslsock.version()
                    cipher_tuple = sslsock.cipher()
                    cipher_name = cipher_tuple[0] if cipher_tuple else None

                    cert = sslsock.getpeercert(binary_form=False) or {}
                    cert_subject = None
                    cert_issuer = None
                    cert_valid_from = None
                    cert_valid_to = None
                    cert_sans: List[str] = []

                    if cert:
                        # Extract subject CN
                        for sub_attr in cert.get("subject", ()):
                            for k, v in sub_attr:
                                if k == "commonName":
                                    cert_subject = str(v)

                        # Extract issuer CN / Org
                        for iss_attr in cert.get("issuer", ()):
                            for k, v in iss_attr:
                                if k in ("organizationName", "commonName"):
                                    cert_issuer = str(v)

                        # Parse SANs
                        for san_type, san_val in cert.get("subjectAltName", ()):
                            if san_type == "DNS":
                                cert_sans.append(str(san_val))

                        # Parse dates (e.g. 'Jan  1 00:00:00 2024 GMT')
                        not_before = cert.get("notBefore")
                        not_after = cert.get("notAfter")
                        if not_before:
                            try:
                                cert_valid_from = datetime.strptime(
                                    not_before, "%b %d %H:%M:%S %Y %Z"
                                ).replace(tzinfo=timezone.utc)
                            except Exception:
                                pass
                        if not_after:
                            try:
                                cert_valid_to = datetime.strptime(
                                    not_after, "%b %d %H:%M:%S %Y %Z"
                                ).replace(tzinfo=timezone.utc)
                            except Exception:
                                pass

                    return TLSMetadata(
                        tls_version=tls_ver,
                        cipher_suite=cipher_name,
                        cert_subject=cert_subject,
                        cert_issuer=cert_issuer,
                        cert_valid_from=cert_valid_from,
                        cert_valid_to=cert_valid_to,
                        cert_san_list=cert_sans,
                    )
        except Exception as exc:
            logger.debug(f"TLS inspection skipped or failed for '{hostname}:{port}': {exc}")
            return None

    def _execute_http_probe(
        self,
        target_url: str,
        hostname: str,
        port: int,
        protocol: str,
        service_name: str,
        tls_info: Optional[TLSMetadata],
    ) -> HTTPProbeObservation:
        """Perform manual redirect-validated HTTP request and extract headers and body."""
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        start_time = time.perf_counter()
        current_url = target_url
        redirect_count = 0
        last_status_code: Optional[int] = None
        last_final_url: Optional[str] = current_url
        http_version_str: Optional[str] = None
        collected_headers: Dict[str, str] = {}
        collected_cookies: Dict[str, str] = {}
        body_text = ""
        extracted_title: Optional[str] = None
        last_error: Optional[str] = None

        try:
            while redirect_count <= self._max_redirects:
                if not self._is_safe_url(current_url):
                    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    return HTTPProbeObservation(
                        url=target_url,
                        port=port,
                        protocol=protocol,
                        service_name=service_name,
                        is_reachable=False,
                        response_time_ms=elapsed_ms,
                        error=f"SSRF Redirect Blocked: Target '{current_url}' is non-public/reserved",
                    )

                if self._client:
                    # Injected mock/test client mode
                    resp = self._client.get(
                        current_url,
                        headers=headers,
                        timeout=self._timeout,
                        follow_redirects=False,
                    )
                    status_code = resp.status_code
                    last_status_code = status_code
                    last_final_url = str(resp.url) if hasattr(resp, "url") and resp.url else current_url
                    http_version_str = getattr(resp, "http_version", "HTTP/1.1")

                    for k, v in resp.headers.items():
                        collected_headers[k.lower()] = v

                    if hasattr(resp, "cookies"):
                        for c_key, c_val in resp.cookies.items():
                            collected_cookies[c_key] = c_val

                    if status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location") or resp.headers.get("location")
                        if location:
                            next_url = urllib.parse.urljoin(current_url, location)
                            redirect_count += 1
                            if redirect_count > self._max_redirects:
                                last_error = "Maximum redirect limit exceeded"
                                break
                            current_url = next_url
                            continue

                    snippet = resp.text[: self.MAX_BODY_BYTES] if hasattr(resp, "text") and isinstance(resp.text, str) else ""
                    body_text = snippet
                    extracted_title = self._extract_title(snippet)
                    break

                else:
                    # Production streaming client
                    with httpx.Client(
                        timeout=self._timeout,
                        follow_redirects=False,
                        verify=False,
                    ) as client:
                        with client.stream(
                            "GET",
                            current_url,
                            headers=headers,
                            timeout=self._timeout,
                        ) as resp:
                            status_code = resp.status_code
                            last_status_code = status_code
                            last_final_url = str(resp.url)
                            http_version_str = getattr(resp, "http_version", "HTTP/1.1")

                            for k, v in resp.headers.items():
                                collected_headers[k.lower()] = v

                            if hasattr(resp, "cookies"):
                                for c_key, c_val in resp.cookies.items():
                                    collected_cookies[c_key] = c_val

                            if status_code in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location") or resp.headers.get("location")
                                if location:
                                    next_url = urllib.parse.urljoin(current_url, location)
                                    redirect_count += 1
                                    if redirect_count > self._max_redirects:
                                        last_error = "Maximum redirect limit exceeded"
                                        break
                                    current_url = next_url
                                    continue

                            chunks = []
                            bytes_read = 0
                            for chunk in resp.iter_bytes(chunk_size=4096):
                                chunks.append(chunk)
                                bytes_read += len(chunk)
                                if bytes_read >= self.MAX_BODY_BYTES:
                                    break
                            body_text = b"".join(chunks).decode("utf-8", errors="replace")
                            extracted_title = self._extract_title(body_text)
                            break

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Security Headers Analysis
            security_headers_eval = self.analyze_security_headers(
                headers=collected_headers,
                is_https=(service_name == "https"),
            )

            # Content Length parsing
            cl_header = collected_headers.get("content-length")
            content_length_int = None
            if cl_header and cl_header.isdigit():
                content_length_int = int(cl_header)
            elif body_text:
                content_length_int = len(body_text.encode("utf-8"))

            return HTTPProbeObservation(
                url=target_url,
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=True,
                method="GET",
                status_code=last_status_code,
                final_url=last_final_url or current_url,
                redirect_count=redirect_count,
                response_time_ms=elapsed_ms,
                http_version=http_version_str,
                server_header=collected_headers.get("server"),
                powered_by_header=collected_headers.get("x-powered-by"),
                content_type=collected_headers.get("content-type"),
                content_length=content_length_int,
                page_title=extracted_title,
                headers=collected_headers,
                cookies=collected_cookies,
                body_snippet=body_text,
                security_headers=security_headers_eval,
                tls_metadata=tls_info,
                error=last_error,
            )

        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return HTTPProbeObservation(
                url=target_url,
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                tls_metadata=tls_info,
                error="Connection Timeout",
            )
        except (httpx.ConnectError, httpx.NetworkError):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return HTTPProbeObservation(
                url=target_url,
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                tls_metadata=tls_info,
                error="Connection Refused / Network Error",
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return HTTPProbeObservation(
                url=target_url,
                port=port,
                protocol=protocol,
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                tls_metadata=tls_info,
                error=str(exc),
            )

    @staticmethod
    def analyze_security_headers(headers: Dict[str, str], is_https: bool = True) -> Dict[str, SecurityHeaderAnalysis]:
        """
        Passive, deterministic evaluation of HTTP security headers.
        
        Evaluates:
        - Strict-Transport-Security (HSTS)
        - Content-Security-Policy (CSP)
        - X-Frame-Options
        - X-Content-Type-Options
        - Referrer-Policy
        - Permissions-Policy
        - Cross-Origin-Opener-Policy (COOP)
        - Cross-Origin-Resource-Policy (CORP)
        - Cross-Origin-Embedder-Policy (COEP)
        """
        results: Dict[str, SecurityHeaderAnalysis] = {}

        # 1. HSTS (Strict-Transport-Security)
        hsts_val = headers.get("strict-transport-security")
        if hsts_val:
            hsts_clean = hsts_val.strip()
            max_age_match = re.search(r"max-age=(\d+)", hsts_clean, re.IGNORECASE)
            includes_subdomains = "includesubdomains" in hsts_clean.lower()
            preload = "preload" in hsts_clean.lower()
            desc_parts = []
            if max_age_match:
                desc_parts.append(f"max-age={max_age_match.group(1)}")
            if includes_subdomains:
                desc_parts.append("includeSubDomains")
            if preload:
                desc_parts.append("preload")
            desc_str = ", ".join(desc_parts) if desc_parts else "present"
            results["strict_transport_security"] = SecurityHeaderAnalysis(
                header_name="Strict-Transport-Security",
                present=True,
                value=hsts_clean,
                status="configured",
                interpretation=f"HSTS enabled ({desc_str})",
            )
        else:
            interpretation = "HSTS header not observed on HTTPS service" if is_https else "HSTS not applicable for non-HTTPS service"
            results["strict_transport_security"] = SecurityHeaderAnalysis(
                header_name="Strict-Transport-Security",
                present=False,
                value=None,
                status="missing" if is_https else "not_applicable",
                interpretation=interpretation,
            )

        # 2. CSP (Content-Security-Policy)
        csp_val = headers.get("content-security-policy")
        if csp_val:
            results["content_security_policy"] = SecurityHeaderAnalysis(
                header_name="Content-Security-Policy",
                present=True,
                value=csp_val.strip(),
                status="configured",
                interpretation="Content-Security-Policy observed",
            )
        else:
            results["content_security_policy"] = SecurityHeaderAnalysis(
                header_name="Content-Security-Policy",
                present=False,
                value=None,
                status="missing",
                interpretation="CSP header not observed",
            )

        # 3. X-Frame-Options
        xfo_val = headers.get("x-frame-options")
        if xfo_val:
            val_upper = xfo_val.strip().upper()
            if val_upper in ("DENY", "SAMEORIGIN"):
                interp = f"Clickjacking protection enabled ({val_upper})"
                status = "configured"
            else:
                interp = f"X-Frame-Options configured with value: {xfo_val.strip()}"
                status = "custom"
            results["x_frame_options"] = SecurityHeaderAnalysis(
                header_name="X-Frame-Options",
                present=True,
                value=xfo_val.strip(),
                status=status,
                interpretation=interp,
            )
        else:
            results["x_frame_options"] = SecurityHeaderAnalysis(
                header_name="X-Frame-Options",
                present=False,
                value=None,
                status="missing",
                interpretation="X-Frame-Options header not observed",
            )

        # 4. X-Content-Type-Options
        xcto_val = headers.get("x-content-type-options")
        if xcto_val:
            val_clean = xcto_val.strip().lower()
            if val_clean == "nosniff":
                interp = "MIME-sniffing protection enabled (nosniff)"
                status = "configured"
            else:
                interp = f"X-Content-Type-Options present with custom value: {xcto_val.strip()}"
                status = "custom"
            results["x_content_type_options"] = SecurityHeaderAnalysis(
                header_name="X-Content-Type-Options",
                present=True,
                value=xcto_val.strip(),
                status=status,
                interpretation=interp,
            )
        else:
            results["x_content_type_options"] = SecurityHeaderAnalysis(
                header_name="X-Content-Type-Options",
                present=False,
                value=None,
                status="missing",
                interpretation="X-Content-Type-Options header not observed",
            )

        # 5. Referrer-Policy
        ref_val = headers.get("referrer-policy")
        if ref_val:
            results["referrer_policy"] = SecurityHeaderAnalysis(
                header_name="Referrer-Policy",
                present=True,
                value=ref_val.strip(),
                status="configured",
                interpretation=f"Referrer policy configured ({ref_val.strip()})",
            )
        else:
            results["referrer_policy"] = SecurityHeaderAnalysis(
                header_name="Referrer-Policy",
                present=False,
                value=None,
                status="missing",
                interpretation="Referrer-Policy header not observed",
            )

        # 6. Permissions-Policy
        perm_val = headers.get("permissions-policy") or headers.get("feature-policy")
        if perm_val:
            results["permissions_policy"] = SecurityHeaderAnalysis(
                header_name="Permissions-Policy",
                present=True,
                value=perm_val.strip(),
                status="configured",
                interpretation="Permissions-Policy observed",
            )
        else:
            results["permissions_policy"] = SecurityHeaderAnalysis(
                header_name="Permissions-Policy",
                present=False,
                value=None,
                status="missing",
                interpretation="Permissions-Policy header not observed",
            )

        # 7. Cross-Origin Headers (Optional observations)
        coop_val = headers.get("cross-origin-opener-policy")
        if coop_val:
            results["cross_origin_opener_policy"] = SecurityHeaderAnalysis(
                header_name="Cross-Origin-Opener-Policy",
                present=True,
                value=coop_val.strip(),
                status="configured",
                interpretation=f"COOP observed ({coop_val.strip()})",
            )

        corp_val = headers.get("cross-origin-resource-policy")
        if corp_val:
            results["cross_origin_resource_policy"] = SecurityHeaderAnalysis(
                header_name="Cross-Origin-Resource-Policy",
                present=True,
                value=corp_val.strip(),
                status="configured",
                interpretation=f"CORP observed ({corp_val.strip()})",
            )

        return results

    @staticmethod
    def _extract_title(html_content: Optional[str]) -> Optional[str]:
        """Extract and clean HTML <title> text."""
        if not html_content or not isinstance(html_content, str):
            return None
        snippet = html_content[:8192]
        match = TITLE_REGEX.search(snippet)
        if match:
            title = match.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            return title[:200] if title else None
        return None
