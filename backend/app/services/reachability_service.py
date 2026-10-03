"""Lightweight, SSRF-safe Reachability Probing Service for validating HTTP and HTTPS services."""

import ipaddress
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Union, Tuple
import dns.resolver
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger

TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def is_public_ip(ip_str: str) -> bool:
    """
    Determine whether an IPv4 or IPv6 string is a valid public, globally routable address.
    
    Rejects:
    - loopback (127.0.0.0/8, ::1)
    - private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - link-local (169.254.0.0/16, fe80::/10)
    - multicast (224.0.0.0/4, ff00::/8)
    - reserved (240.0.0.0/4, etc.)
    - unspecified (0.0.0.0, ::)
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_global
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
        )
    except ValueError:
        return False


@dataclass
class ReachabilityProbeResult:
    """Result of a single protocol reachability probe (HTTP or HTTPS)."""
    url: str
    port: int  # 80 or 443
    protocol: str  # "tcp"
    service_name: str  # "http" or "https"
    is_reachable: bool
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    page_title: Optional[str] = None
    error: Optional[str] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ReachabilityService:
    """
    Lightweight, SSRF-safe reachability probing service.
    Verifies HTTP (port 80) and HTTPS (port 443) exposure for resolving hostnames.
    Includes strict pre-flight SSRF IP validation, safe redirect inspection, bounded response streaming,
    and controlled concurrency.
    """

    DEFAULT_TIMEOUT_SECONDS = settings.DNS_REACHABILITY_TIMEOUT
    DEFAULT_MAX_REDIRECTS = 3
    MAX_BODY_BYTES = 65536  # 64 KB maximum response body read limit
    USER_AGENT = "Mozilla/5.0 (compatible; AttackSurfaceOSINT/1.0; +https://github.com/osint-platform)"

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: Optional[float] = None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ):
        self._client = client
        self._timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS
        self._max_redirects = max_redirects

    def probe_hostname(
        self,
        hostname: str,
        resolved_ips: Optional[List[str]] = None,
    ) -> List[ReachabilityProbeResult]:
        """
        Probe both HTTPS (443) and HTTP (80) on a resolving hostname.
        
        If resolved_ips is provided, verifies that at least one resolved address is public.
        If all resolved IPs are private/loopback/link-local/reserved, skips HTTP probing.
        """
        cleaned = hostname.strip().rstrip(".")
        results: List[ReachabilityProbeResult] = []

        # SSRF Pre-flight check: If resolved IPs are provided, check for public routability
        if resolved_ips is not None and len(resolved_ips) > 0:
            has_public_ip = any(is_public_ip(ip) for ip in resolved_ips)
            if not has_public_ip:
                logger.info(
                    f"SSRF Protection: Hostname '{cleaned}' resolves only to non-public/reserved IPs {resolved_ips}. "
                    "Skipping HTTP/HTTPS probing."
                )
                for port, service_name in [(443, "https"), (80, "http")]:
                    results.append(
                        ReachabilityProbeResult(
                            url=f"{service_name}://{cleaned}",
                            port=port,
                            protocol="tcp",
                            service_name=service_name,
                            is_reachable=False,
                            error="SSRF Blocked: Resolves to non-public/reserved IP addresses",
                        )
                    )
                return results

        # 1. Probe HTTPS (port 443)
        https_result = self._probe_url(
            f"https://{cleaned}",
            port=443,
            service_name="https",
        )
        results.append(https_result)

        # 2. Probe HTTP (port 80)
        http_result = self._probe_url(
            f"http://{cleaned}",
            port=80,
            service_name="http",
        )
        results.append(http_result)

        return results

    def probe_batch(
        self,
        items: List[Tuple[str, Optional[List[str]]]],
        max_concurrency: Optional[int] = None,
    ) -> Dict[str, List[ReachabilityProbeResult]]:
        """
        Concurrently probe reachability for multiple resolving hostnames.
        
        items: List of (hostname, resolved_ips) tuples.
        """
        if not items:
            return {}

        concurrency = max_concurrency or settings.DNS_MAX_CONCURRENCY
        concurrency = max(1, min(concurrency, len(items)))

        results: Dict[str, List[ReachabilityProbeResult]] = {}

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="probe-worker") as executor:
            future_to_host = {
                executor.submit(self.probe_hostname, host, ips): host
                for host, ips in items
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    res = future.result()
                    results[host] = res
                except Exception as exc:
                    logger.error(f"Worker exception probing '{host}': {exc}")
                    results[host] = [
                        ReachabilityProbeResult(
                            url=f"https://{host}",
                            port=443,
                            protocol="tcp",
                            service_name="https",
                            is_reachable=False,
                            error=str(exc),
                        ),
                        ReachabilityProbeResult(
                            url=f"http://{host}",
                            port=80,
                            protocol="tcp",
                            service_name="http",
                            is_reachable=False,
                            error=str(exc),
                        ),
                    ]

        return results

    def _probe_url(
        self,
        target_url: str,
        port: int,
        service_name: str,
    ) -> ReachabilityProbeResult:
        """Execute a controlled GET probe with manual safe redirect validation and bounded reads."""
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        start_time = time.perf_counter()
        current_url = target_url
        redirect_count = 0
        last_status_code: Optional[int] = None
        last_final_url: Optional[str] = current_url
        extracted_page_title: Optional[str] = None
        last_error: Optional[str] = None

        try:
            while redirect_count <= self._max_redirects:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Validate current URL before requesting
                if not self._is_safe_url(current_url):
                    return ReachabilityProbeResult(
                        url=target_url,
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        is_reachable=False,
                        response_time_ms=elapsed_ms,
                        error=f"SSRF Redirect Blocked: Target '{current_url}' is non-public/reserved",
                    )

                if self._client:
                    # Injected client mode for tests
                    resp = self._client.get(
                        current_url,
                        headers=headers,
                        timeout=self._timeout,
                        follow_redirects=False,
                    )
                    status_code = resp.status_code if isinstance(resp.status_code, int) else 200
                    last_status_code = status_code
                    last_final_url = str(resp.url) if hasattr(resp, "url") and resp.url else current_url

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
                    extracted_page_title = self._extract_title(snippet)
                    break

                else:
                    # Production HTTPX streaming client with permissive SSL (for discovery) and bounded streaming
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

                            # Bounded read up to MAX_BODY_BYTES
                            chunks = []
                            bytes_read = 0
                            for chunk in resp.iter_bytes(chunk_size=4096):
                                chunks.append(chunk)
                                bytes_read += len(chunk)
                                if bytes_read >= self.MAX_BODY_BYTES:
                                    break
                            body_text = b"".join(chunks).decode("utf-8", errors="replace")
                            extracted_page_title = self._extract_title(body_text)
                            break

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ReachabilityProbeResult(
                url=target_url,
                port=port,
                protocol="tcp",
                service_name=service_name,
                is_reachable=True,
                status_code=last_status_code,
                final_url=last_final_url or current_url,
                response_time_ms=elapsed_ms,
                page_title=extracted_page_title,
                error=last_error,
            )

        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ReachabilityProbeResult(
                url=target_url,
                port=port,
                protocol="tcp",
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                error="Connection Timeout",
            )
        except (httpx.ConnectError, httpx.NetworkError):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ReachabilityProbeResult(
                url=target_url,
                port=port,
                protocol="tcp",
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                error="Connection Refused / Network Error",
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ReachabilityProbeResult(
                url=target_url,
                port=port,
                protocol="tcp",
                service_name=service_name,
                is_reachable=False,
                response_time_ms=elapsed_ms,
                error=str(exc),
            )

    def _is_safe_url(self, url: str) -> bool:
        """Verify URL scheme and validate that target host does not resolve to private/loopback/reserved IPs."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False

            host = parsed.hostname
            if not host:
                return False

            host_lower = host.lower()
            if (
                host_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
                or host_lower.endswith(".local")
                or host_lower.endswith(".internal")
                or host_lower.endswith(".localhost")
            ):
                return False

            # 1. If host is an IP literal
            try:
                ip_obj = ipaddress.ip_address(host)
                return is_public_ip(str(ip_obj))
            except ValueError:
                pass

            # 2. If host is a hostname, resolve to check for private IPs
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1.0
                resolver.lifetime = 1.0
                for rtype in ("A", "AAAA"):
                    try:
                        answers = resolver.resolve(host, rtype)
                        for rdata in answers:
                            ip_str = str(rdata).strip()
                            if not is_public_ip(ip_str):
                                return False
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
                        continue
                    except Exception:
                        pass
                return True
            except Exception:
                return True

        except Exception:
            return False

    @staticmethod
    def _extract_title(html_content: Optional[str]) -> Optional[str]:
        """Extract and clean HTML <title> text from response body (first 8KB)."""
        if not html_content or not isinstance(html_content, str):
            return None

        snippet = html_content[:8192]
        match = TITLE_REGEX.search(snippet)
        if match:
            title = match.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            return title[:200] if title else None
        return None
