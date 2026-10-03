"""ASN (Autonomous System Number) intelligence service and provider abstraction."""

import threading
import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import dns.resolver

from backend.app.core.logging import logger
from backend.app.services.ip_service import is_public_ip, validate_and_normalize_ip


@dataclass
class ASNInfo:
    """Structured Autonomous System & network routing intelligence."""
    asn_number: Optional[int]
    name: Optional[str] = None
    country: Optional[str] = None
    allocated_prefix: Optional[str] = None
    registry: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class BaseASNProvider(ABC):
    """Abstract base class for ASN intelligence providers."""

    @abstractmethod
    def lookup(self, ip: str) -> Optional[ASNInfo]:
        """Lookup ASN intelligence for a public IP address."""
        raise NotImplementedError


class CymruDNSASNProvider(BaseASNProvider):
    """
    Standard DNS TXT-based ASN enrichment provider using Team Cymru's public mapping service.
    
    Queries:
    - IPv4: <reversed-ip>.origin.asn.cymru.com
    - IPv6: <reversed-nibbles>.origin6.asn.cymru.com
    - AS Name: AS<asn>.asn.cymru.com
    """

    def __init__(self, timeout: float = 1.5, lifetime: float = 2.0):
        self.timeout = timeout
        self.lifetime = lifetime
        self._asn_name_cache: Dict[int, Optional[str]] = {}
        self._cache_lock = threading.Lock()

    def _get_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime
        return resolver

    def _format_ipv6_reverse_cymru(self, ip_obj: ipaddress.IPv6Address) -> str:
        """Format an IPv6 address into dot-separated reversed nibbles for origin6.asn.cymru.com."""
        hex_str = ip_obj.exploded.replace(":", "")
        reversed_nibbles = ".".join(reversed(hex_str))
        return f"{reversed_nibbles}.origin6.asn.cymru.com"

    def _lookup_as_name(self, asn: int, resolver: dns.resolver.Resolver) -> Optional[str]:
        """Query AS<asn>.asn.cymru.com for the organization name with caching."""
        with self._cache_lock:
            if asn in self._asn_name_cache:
                return self._asn_name_cache[asn]

        name = None
        try:
            as_query = f"AS{asn}.asn.cymru.com"
            answers = resolver.resolve(as_query, "TXT")
            for rdata in answers:
                # Format: "15169 | US | arin | 2000-01-01 | GOOGLE, US"
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 5:
                    name = parts[4].strip()
                    break
                elif len(parts) >= 1:
                    name = parts[-1].strip()
                    break
        except Exception:
            pass

        with self._cache_lock:
            self._asn_name_cache[asn] = name

        return name

    def lookup(self, ip: str) -> Optional[ASNInfo]:
        """Perform DNS TXT query to retrieve ASN information for an IP."""
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None

        resolver = self._get_resolver()

        try:
            if ip_obj.version == 4:
                # 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
                reversed_ip = ".".join(reversed(ip_obj.exploded.split(".")))
                query_name = f"{reversed_ip}.origin.asn.cymru.com"
            else:
                query_name = self._format_ipv6_reverse_cymru(ip_obj)

            answers = resolver.resolve(query_name, "TXT")
            for rdata in answers:
                # Format: "15169 | 8.8.8.0/24 | US | arin | 2000-01-01"
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                parts = [p.strip() for p in txt.split("|")]

                if len(parts) >= 1:
                    asn_str = parts[0].split()[0] if parts[0] else ""
                    try:
                        asn_number = int(asn_str)
                    except ValueError:
                        asn_number = None

                    allocated_prefix = parts[1] if len(parts) > 1 and parts[1] else None
                    country = parts[2] if len(parts) > 2 and parts[2] else None
                    registry = parts[3] if len(parts) > 3 and parts[3] else None

                    org_name = None
                    if asn_number:
                        org_name = self._lookup_as_name(asn_number, resolver)

                    return ASNInfo(
                        asn_number=asn_number,
                        name=org_name or (f"AS{asn_number}" if asn_number else None),
                        country=country,
                        allocated_prefix=allocated_prefix,
                        registry=registry,
                        raw_data={"txt": txt, "source": "origin.asn.cymru.com"},
                    )

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.debug(f"No ASN mapping found for IP '{ip}'")
            return None
        except dns.exception.Timeout:
            logger.warning(f"Timeout querying ASN for IP '{ip}'")
            return None
        except Exception as exc:
            logger.warning(f"Error querying ASN for IP '{ip}': {exc}")
            return None

        return None


class ASNService:
    """Service coordinating ASN and routing network enrichment."""

    def __init__(self, provider: Optional[BaseASNProvider] = None):
        self.provider = provider or CymruDNSASNProvider()

    def lookup(self, ip_str: str) -> Optional[ASNInfo]:
        """
        Lookup ASN intelligence for an IP string.
        
        Skips non-public IPs (private, loopback, link-local, reserved) safely.
        """
        parsed = validate_and_normalize_ip(ip_str)
        if not parsed:
            return None

        normalized_ip, _, is_public = parsed
        if not is_public:
            logger.info(f"Skipping ASN lookup for non-public IP '{normalized_ip}'")
            return None

        return self.provider.lookup(normalized_ip)
