"""RDAP (Registration Data Access Protocol) intelligence service for IP address registration information."""

import json
import time
import threading
import urllib.parse
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple, Union
import dns.resolver
import dns.exception
import httpx

from backend.app.core.logging import logger
from backend.app.services.ip_service import is_public_ip, validate_and_normalize_ip


ALLOWED_RDAP_HOSTS = {
    "rdap.arin.net",
    "rdap.db.ripe.net",
    "rdap.apnic.net",
    "rdap.lacnic.net",
    "rdap.afrinic.net",
    "rdap.iana.org",
    "rdap.nic.ad.jp",
    "rdap.nic.br",
    "rdap.krnic.net",
    "rdap.twnic.tw",
}


@dataclass
class RDAPInfo:
    """Structured, normalized RDAP network registration intelligence."""
    ip: str
    network_name: Optional[str] = None
    handle: Optional[str] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    cidr: Optional[str] = None
    country: Optional[str] = None
    organization: Optional[str] = None
    status: List[str] = field(default_factory=list)
    registration_date: Optional[datetime] = None
    last_changed_date: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    raw_json_str: Optional[str] = None


class RDAPBootstrap:
    """
    Authoritative IANA RDAP Bootstrap discovery provider for IPv4 and IPv6 address space.
    
    Implements RFC 7484 / RFC 9224 bootstrap service determination based on IANA registry allocations:
    - AFRINIC: https://rdap.afrinic.net/rdap/
    - APNIC:   https://rdap.apnic.net/
    - ARIN:    https://rdap.arin.net/registry/
    - LACNIC:  https://rdap.lacnic.net/rdap/
    - RIPE:    https://rdap.db.ripe.net/
    """

    # Canonical IANA IPv4 prefix allocations
    DEFAULT_IPV4_SERVICES = [
        # AFRINIC
        (
            ["41.0.0.0/8", "102.0.0.0/8", "105.0.0.0/8", "154.0.0.0/8", "196.0.0.0/8", "197.0.0.0/8"],
            "https://rdap.afrinic.net/rdap/",
        ),
        # APNIC
        (
            [
                "1.0.0.0/8", "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8", "39.0.0.0/8", "42.0.0.0/8", "43.0.0.0/8",
                "49.0.0.0/8", "58.0.0.0/8", "59.0.0.0/8", "60.0.0.0/8", "61.0.0.0/8", "101.0.0.0/8", "103.0.0.0/8",
                "106.0.0.0/8", "110.0.0.0/8", "111.0.0.0/8", "112.0.0.0/8", "113.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8",
                "116.0.0.0/8", "117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8", "120.0.0.0/8", "121.0.0.0/8", "122.0.0.0/8",
                "123.0.0.0/8", "124.0.0.0/8", "125.0.0.0/8", "126.0.0.0/8", "133.0.0.0/8", "150.0.0.0/8", "153.0.0.0/8",
                "163.0.0.0/8", "171.0.0.0/8", "175.0.0.0/8", "180.0.0.0/8", "182.0.0.0/8", "183.0.0.0/8", "202.0.0.0/8",
                "203.0.0.0/8", "210.0.0.0/8", "211.0.0.0/8", "218.0.0.0/8", "219.0.0.0/8", "220.0.0.0/8", "221.0.0.0/8",
                "222.0.0.0/8", "223.0.0.0/8",
            ],
            "https://rdap.apnic.net/",
        ),
        # LACNIC
        (
            [
                "177.0.0.0/8", "179.0.0.0/8", "181.0.0.0/8", "186.0.0.0/8", "187.0.0.0/8",
                "189.0.0.0/8", "190.0.0.0/8", "191.0.0.0/8", "200.0.0.0/8", "201.0.0.0/8",
            ],
            "https://rdap.lacnic.net/rdap/",
        ),
        # RIPE NCC
        (
            [
                "2.0.0.0/8", "5.0.0.0/8", "25.0.0.0/8", "31.0.0.0/8", "37.0.0.0/8", "46.0.0.0/8", "51.0.0.0/8",
                "53.0.0.0/8", "57.0.0.0/8", "62.0.0.0/8", "77.0.0.0/8", "78.0.0.0/8", "79.0.0.0/8", "80.0.0.0/8",
                "81.0.0.0/8", "82.0.0.0/8", "83.0.0.0/8", "84.0.0.0/8", "85.0.0.0/8", "86.0.0.0/8", "87.0.0.0/8",
                "88.0.0.0/8", "89.0.0.0/8", "90.0.0.0/8", "91.0.0.0/8", "92.0.0.0/8", "93.0.0.0/8", "94.0.0.0/8",
                "95.0.0.0/8", "109.0.0.0/8", "141.0.0.0/8", "145.0.0.0/8", "151.0.0.0/8", "176.0.0.0/8", "178.0.0.0/8",
                "185.0.0.0/8", "188.0.0.0/8", "193.0.0.0/8", "194.0.0.0/8", "195.0.0.0/8", "212.0.0.0/8", "213.0.0.0/8",
                "217.0.0.0/8",
            ],
            "https://rdap.db.ripe.net/",
        ),
        # ARIN
        (
            [
                "3.0.0.0/8", "8.0.0.0/8", "9.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8",
                "16.0.0.0/8", "17.0.0.0/8", "18.0.0.0/8", "19.0.0.0/8", "20.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8",
                "23.0.0.0/8", "24.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "32.0.0.0/8",
                "33.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8", "38.0.0.0/8", "40.0.0.0/8", "44.0.0.0/8", "45.0.0.0/8",
                "47.0.0.0/8", "48.0.0.0/8", "50.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "55.0.0.0/8", "56.0.0.0/8",
                "63.0.0.0/8", "64.0.0.0/8", "65.0.0.0/8", "66.0.0.0/8", "67.0.0.0/8", "68.0.0.0/8", "69.0.0.0/8",
                "70.0.0.0/8", "71.0.0.0/8", "72.0.0.0/8", "73.0.0.0/8", "74.0.0.0/8", "75.0.0.0/8", "76.0.0.0/8",
                "96.0.0.0/8", "97.0.0.0/8", "98.0.0.0/8", "99.0.0.0/8", "100.0.0.0/8", "104.0.0.0/8", "107.0.0.0/8",
                "108.0.0.0/8", "128.0.0.0/8", "129.0.0.0/8", "130.0.0.0/8", "131.0.0.0/8", "132.0.0.0/8", "134.0.0.0/8",
                "135.0.0.0/8", "136.0.0.0/8", "137.0.0.0/8", "138.0.0.0/8", "139.0.0.0/8", "140.0.0.0/8", "142.0.0.0/8",
                "143.0.0.0/8", "144.0.0.0/8", "146.0.0.0/8", "147.0.0.0/8", "148.0.0.0/8", "149.0.0.0/8", "152.0.0.0/8",
                "155.0.0.0/8", "156.0.0.0/8", "157.0.0.0/8", "158.0.0.0/8", "159.0.0.0/8", "160.0.0.0/8", "161.0.0.0/8",
                "162.0.0.0/8", "164.0.0.0/8", "165.0.0.0/8", "166.0.0.0/8", "167.0.0.0/8", "168.0.0.0/8", "169.0.0.0/8",
                "170.0.0.0/8", "172.0.0.0/8", "173.0.0.0/8", "174.0.0.0/8", "184.0.0.0/8", "192.0.0.0/8", "198.0.0.0/8",
                "199.0.0.0/8", "204.0.0.0/8", "205.0.0.0/8", "206.0.0.0/8", "207.0.0.0/8", "208.0.0.0/8", "209.0.0.0/8",
                "216.0.0.0/8",
            ],
            "https://rdap.arin.net/registry/",
        ),
    ]

    # Canonical IANA IPv6 prefix allocations
    DEFAULT_IPV6_SERVICES = [
        # AFRINIC
        (["2001:4200::/23", "2001:4300::/24", "2c00::/12"], "https://rdap.afrinic.net/rdap/"),
        # APNIC
        (["2001:200::/23", "2001:400::/23", "2001:800::/23", "2001:e00::/23", "2400::/12"], "https://rdap.apnic.net/"),
        # LACNIC
        (["2001:1200::/23", "2800::/12"], "https://rdap.lacnic.net/rdap/"),
        # RIPE NCC
        (
            [
                "2001:600::/23", "2001:800::/22", "2001:1400::/23", "2001:1600::/23", "2001:1a00::/23",
                "2001:1c00::/22", "2001:2000::/20", "2001:3000::/21", "2001:3800::/22", "2001:4000::/23",
                "2001:4600::/23", "2001:4a00::/23", "2001:4c00::/23", "2001:5000::/20", "2a00::/12",
            ],
            "https://rdap.db.ripe.net/",
        ),
        # ARIN
        (
            [
                "2001:4800::/23", "2600::/12", "2610::/23", "2620::/23", "2630::/12",
                "2606::/16", "2607::/16",
            ],
            "https://rdap.arin.net/registry/",
        ),
    ]

    def __init__(self):
        self._ipv4_registry: List[Tuple[ipaddress.IPv4Network, str]] = []
        self._ipv6_registry: List[Tuple[ipaddress.IPv6Network, str]] = []
        self.reset_to_defaults()

    def reset_to_defaults(self) -> None:
        """Reset internal registries to default canonical IANA mappings."""
        self._ipv4_registry = []
        for prefixes, url in self.DEFAULT_IPV4_SERVICES:
            for prefix in prefixes:
                try:
                    self._ipv4_registry.append((ipaddress.IPv4Network(prefix, strict=False), url))
                except ValueError:
                    pass

        self._ipv6_registry = []
        for prefixes, url in self.DEFAULT_IPV6_SERVICES:
            for prefix in prefixes:
                try:
                    self._ipv6_registry.append((ipaddress.IPv6Network(prefix, strict=False), url))
                except ValueError:
                    pass

    def load_bootstrap_registry(self, data: Dict[str, Any], ip_version: int) -> bool:
        """
        Load bootstrap data formatted according to RFC 7484 / IANA JSON bootstrap specifications:
        {
            "version": "1.0",
            "services": [
                [
                    ["1.0.0.0/8", "27.0.0.0/8"],
                    ["https://rdap.apnic.net/"]
                ]
            ]
        }
        """
        try:
            services = data.get("services", [])
            if not isinstance(services, list):
                return False

            new_entries = []
            for entry in services:
                if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                    continue
                prefixes, urls = entry[0], entry[1]
                if not prefixes or not urls or not isinstance(urls, list) or len(urls) == 0:
                    continue
                base_url = str(urls[0])

                for prefix_str in prefixes:
                    try:
                        if ip_version == 4:
                            net = ipaddress.IPv4Network(prefix_str, strict=False)
                        else:
                            net = ipaddress.IPv6Network(prefix_str, strict=False)
                        new_entries.append((net, base_url))
                    except ValueError:
                        continue

            if ip_version == 4:
                self._ipv4_registry = new_entries
            else:
                self._ipv6_registry = new_entries

            return True
        except Exception as exc:
            logger.warning(f"Failed to load bootstrap registry data: {exc}")
            return False

    def get_authoritative_base_url(self, ip_str: str) -> Optional[str]:
        """
        Determine the authoritative RIR RDAP base URL for a given IPv4 or IPv6 address.
        
        Returns the base URL (e.g. 'https://rdap.arin.net/registry/') or None if no match.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if ip_obj.version == 4:
                for net, url in self._ipv4_registry:
                    if ip_obj in net:
                        return url
            elif ip_obj.version == 6:
                for net, url in self._ipv6_registry:
                    if ip_obj in net:
                        return url
            return None
        except Exception as exc:
            logger.debug(f"RDAP bootstrap lookup error for IP '{ip_str}': {exc}")
            return None

    def build_ip_url(self, ip_str: str) -> Optional[str]:
        """Construct the complete, authoritative RDAP query URL for an IP address."""
        base_url = self.get_authoritative_base_url(ip_str)
        if not base_url:
            return None
        cleaned_base = base_url.rstrip("/")
        cleaned_ip = ip_str.strip()
        return f"{cleaned_base}/ip/{cleaned_ip}"


class RDAPService:
    """
    Lightweight, SSRF-safe RDAP client for retrieving IP network registration details.
    
    Features:
    - Queries authoritative RIR bootstrap endpoints dynamically based on IANA prefix allocations.
    - Pre-connection DNS validation on all target and redirect destination hostnames with TTL caching.
    - Rejects targets resolving to private, loopback, link-local, multicast, or reserved IPs.
    - Validates redirects against an approved list of RIR domains.
    - Enforces strict response size bounds (128 KB) and bounded request timeouts.
    - Reuses connection pool for low-latency concurrent HTTP/HTTPS communication.
    - Normalizes diverse RIR schema formats into a consistent internal model.
    """

    DEFAULT_TIMEOUT_SECONDS = 3.0
    DEFAULT_MAX_REDIRECTS = 3
    MAX_BODY_BYTES = 131072  # 128 KB
    USER_AGENT = "Mozilla/5.0 (compatible; AttackSurfaceOSINT/1.0; +https://github.com/osint-platform)"

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        bootstrap: Optional[RDAPBootstrap] = None,
        resolver: Optional[Any] = None,
        timeout: Union[float, httpx.Timeout] = DEFAULT_TIMEOUT_SECONDS,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ):
        self._client = client
        self._client_pool: Optional[httpx.Client] = None
        self._client_lock = threading.Lock()
        self._bootstrap = bootstrap or RDAPBootstrap()
        self._resolver = resolver
        self._timeout = timeout
        self._max_redirects = max_redirects

        # Host SSRF validation cache: host -> (is_valid: bool, timestamp: float)
        self._host_validation_cache: Dict[str, Tuple[bool, float]] = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 300.0  # 5 minutes TTL

    def _get_client(self) -> httpx.Client:
        """Get or initialize thread-safe persistent connection-pooled HTTP client."""
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client_pool is None or self._client_pool.is_closed:
                timeout_config = (
                    self._timeout
                    if isinstance(self._timeout, httpx.Timeout)
                    else httpx.Timeout(
                        connect=min(2.0, float(self._timeout)),
                        read=float(self._timeout),
                        write=2.0,
                        pool=2.0,
                    )
                )
                self._client_pool = httpx.Client(
                    timeout=timeout_config,
                    limits=httpx.Limits(
                        max_keepalive_connections=20,
                        max_connections=50,
                        keepalive_expiry=30.0,
                    ),
                    follow_redirects=False,
                    verify=True,
                )
            return self._client_pool

    def close(self) -> None:
        """Close internal connection pool."""
        with self._client_lock:
            if self._client_pool is not None and not self._client_pool.is_closed:
                self._client_pool.close()
                self._client_pool = None

    def __enter__(self) -> "RDAPService":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _get_resolver(self) -> dns.resolver.Resolver:
        if self._resolver is not None:
            return self._resolver
        res = dns.resolver.Resolver()
        res.timeout = 1.5
        res.lifetime = 1.5
        return res

    def _validate_rdap_endpoint(self, url: str) -> bool:
        """
        SSRF Hardening: Verify destination is an authorized HTTPS/HTTP endpoint on an approved RIR host
        and that all resolved A/AAAA addresses are strictly public, globally routable IPs.
        Caches validated hostnames with a 5-minute TTL to eliminate redundant DNS round-trips.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False

            host = (parsed.hostname or "").lower()
            if not host:
                return False

            # 1. Host must belong to approved RDAP allowlist
            if host not in ALLOWED_RDAP_HOSTS:
                logger.warning(f"RDAP target '{host}' rejected: not in approved RDAP host allowlist")
                return False

            # 2. Check if host is an IP literal
            try:
                ip_obj = ipaddress.ip_address(host)
                return is_public_ip(str(ip_obj))
            except ValueError:
                pass

            # 3. Check cached validation
            now = time.time()
            with self._cache_lock:
                if host in self._host_validation_cache:
                    valid, ts = self._host_validation_cache[host]
                    if now - ts < self._cache_ttl:
                        return valid

            # 4. Pre-connection DNS resolution: check that resolved A/AAAA records exist and are all public
            resolved_ips: List[str] = []
            resolver = self._get_resolver()

            for rtype in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(host, rtype)
                    for rdata in answers:
                        resolved_ips.append(str(rdata).strip())
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                except dns.exception.DNSException as exc:
                    logger.debug(f"DNS resolution exception for RDAP host '{host}' ({rtype}): {exc}")
                    continue
                except Exception as exc:
                    logger.debug(f"Unexpected DNS error for RDAP host '{host}' ({rtype}): {exc}")
                    continue

            if not resolved_ips:
                logger.warning(f"RDAP target '{host}' rejected: DNS resolution returned no A/AAAA records")
                with self._cache_lock:
                    self._host_validation_cache[host] = (False, now)
                return False

            # 5. Reject if ANY resolved address is private, loopback, link-local, multicast, or reserved
            for rip in resolved_ips:
                if not is_public_ip(rip):
                    logger.warning(
                        f"SSRF Protection: RDAP destination '{host}' resolved to non-public/reserved IP '{rip}'. Rejecting."
                    )
                    with self._cache_lock:
                        self._host_validation_cache[host] = (False, now)
                    return False

            with self._cache_lock:
                self._host_validation_cache[host] = (True, now)
            return True
        except Exception as exc:
            logger.warning(f"RDAP endpoint validation error for '{url}': {exc}")
            return False

    def lookup(self, ip_str: str) -> Optional[RDAPInfo]:
        """
        Lookup RDAP registration data for a public IPv4 or IPv6 address.
        
        Returns None if:
        - IP is non-public or invalid
        - Bootstrap discovery fails or yields no matching RIR
        - Lookup fails, times out, or returns 404/5xx
        """
        parsed = validate_and_normalize_ip(ip_str)
        if not parsed:
            return None

        normalized_ip, _, is_public = parsed
        if not is_public:
            logger.info(f"Skipping RDAP lookup for non-public IP '{normalized_ip}'")
            return None

        # 1. Authoritative RDAP Bootstrap Discovery
        try:
            current_url = self._bootstrap.build_ip_url(normalized_ip)
        except Exception as exc:
            logger.warning(f"RDAP bootstrap lookup error for IP '{normalized_ip}': {exc}")
            return None

        if not current_url:
            logger.info(f"No authoritative RDAP bootstrap mapping found for IP '{normalized_ip}'")
            return None

        # 2. Validate initial bootstrap endpoint before connection
        if not self._validate_rdap_endpoint(current_url):
            logger.warning(f"Initial RDAP bootstrap endpoint failed security validation: {current_url}")
            return None

        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/rdap+json, application/json",
        }

        redirect_count = 0
        raw_body_bytes = b""
        client = self._get_client()

        try:
            while redirect_count <= self._max_redirects:
                resp = client.get(
                    current_url,
                    headers=headers,
                    timeout=self._timeout,
                    follow_redirects=False,
                )
                status_code = resp.status_code

                if status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location") or resp.headers.get("location")
                    if location:
                        next_url = urllib.parse.urljoin(current_url, location)
                        redirect_count += 1
                        if redirect_count > self._max_redirects:
                            logger.warning(f"RDAP redirect limit ({self._max_redirects}) exceeded for IP '{normalized_ip}'")
                            return None

                        if not self._validate_rdap_endpoint(next_url):
                            logger.warning(f"RDAP redirect to unauthorized or non-public host blocked: {next_url}")
                            return None

                        current_url = next_url
                        continue

                if status_code == 404:
                    logger.debug(f"RDAP 404 not found for IP '{normalized_ip}'")
                    return None
                elif status_code != 200:
                    logger.warning(f"RDAP returned status {status_code} for IP '{normalized_ip}'")
                    return None

                raw_body_bytes = resp.content[: self.MAX_BODY_BYTES] if hasattr(resp, "content") else (resp.text.encode("utf-8")[: self.MAX_BODY_BYTES])
                break

            if not raw_body_bytes:
                return None

            raw_text = raw_body_bytes.decode("utf-8", errors="replace")
            rdap_json = json.loads(raw_text)

            return self._parse_rdap_json(normalized_ip, rdap_json, raw_text)

        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as exc:
            logger.warning(f"Timeout during RDAP lookup for IP '{normalized_ip}': {exc}")
            return None
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            logger.warning(f"Network error during RDAP lookup for IP '{normalized_ip}': {exc}")
            return None
        except json.JSONDecodeError as exc:
            logger.warning(f"Malformed JSON response from RDAP for IP '{normalized_ip}': {exc}")
            return None
        except Exception as exc:
            logger.warning(f"Unexpected error during RDAP lookup for IP '{normalized_ip}': {exc}")
            return None

    def _parse_rdap_json(self, ip: str, data: Dict[str, Any], raw_text: str) -> RDAPInfo:
        """Normalize raw RDAP JSON structure into structured RDAPInfo."""
        network_name = data.get("name")
        handle = data.get("handle")
        start_address = data.get("startAddress")
        end_address = data.get("endAddress")
        country = data.get("country")
        status = data.get("status", [])
        if not isinstance(status, list):
            status = [str(status)]

        # Extract CIDR
        cidr = None
        cidr_list = data.get("cidr0_cidrs")
        if isinstance(cidr_list, list) and len(cidr_list) > 0:
            first = cidr_list[0]
            if isinstance(first, dict):
                prefix = first.get("v4prefix") or first.get("v6prefix")
                length = first.get("length")
                if prefix is not None and length is not None:
                    cidr = f"{prefix}/{length}"

        # Extract Organization / Entity Name
        organization = None
        entities = data.get("entities", [])
        if isinstance(entities, list):
            for ent in entities:
                if isinstance(ent, dict):
                    # Check vcardArray
                    vcard = ent.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                fn_val = str(item[3]).strip()
                                if fn_val:
                                    organization = fn_val
                                    break
                    # If organization not found in vcard, check handle or name
                    if not organization and ent.get("roles"):
                        roles = [str(r).lower() for r in ent.get("roles", [])]
                        if any(r in ("registrant", "administrative", "technical", "abuse") for r in roles):
                            organization = ent.get("handle") or ent.get("name")
                    if organization:
                        break

        # Fallback to remarks or name for organization if still None
        if not organization and network_name:
            organization = network_name

        # Extract Events (registration & last changed)
        registration_date = None
        last_changed_date = None
        events = data.get("events", [])
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict):
                    action = str(ev.get("eventAction", "")).lower()
                    date_str = ev.get("eventDate")
                    if date_str and isinstance(date_str, str):
                        try:
                            clean_dt = date_str.replace("Z", "+00:00")
                            parsed_dt = datetime.fromisoformat(clean_dt)
                            if action == "registration":
                                registration_date = parsed_dt
                            elif action in ("last changed", "last updated", "modification"):
                                last_changed_date = parsed_dt
                        except Exception:
                            pass

        return RDAPInfo(
            ip=ip,
            network_name=network_name,
            handle=handle,
            start_address=start_address,
            end_address=end_address,
            cidr=cidr,
            country=country,
            organization=organization,
            status=status,
            registration_date=registration_date,
            last_changed_date=last_changed_date,
            raw_data=data,
            raw_json_str=raw_text,
        )
