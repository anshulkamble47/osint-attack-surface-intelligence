"""IP address validation, normalization, and classification service."""

import ipaddress
from typing import Optional, Tuple, List, Dict, Any, Sequence, Set
from backend.app.models.asset import DNSRecord
from backend.app.core.logging import logger


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


def validate_and_normalize_ip(ip_str: str) -> Optional[Tuple[str, int, bool]]:
    """
    Validate, normalize, and classify an IP address string.
    
    Returns:
        (normalized_ip_str, ip_version, is_public) or None if invalid.
        
    Examples:
        - " 8.8.8.8 " -> ("8.8.8.8", 4, True)
        - "2001:0db8:0000:0000:0000:0000:0000:0001" -> ("2001:db8::1", 6, False)  # doc range
        - "127.0.0.1" -> ("127.0.0.1", 4, False)
        - "example.com" -> None
        - "999.999.999.999" -> None
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        normalized = ip_obj.compressed
        is_public = (
            ip_obj.is_global
            and not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
            and not ip_obj.is_unspecified
        )
        return (normalized, ip_obj.version, is_public)
    except ValueError:
        return None


class IPService:
    """Service for IP extraction, normalization, deduplication, and classification."""

    @staticmethod
    def normalize_ip(ip_str: str) -> Optional[str]:
        """Normalize an IP address to its standard canonical representation."""
        result = validate_and_normalize_ip(ip_str)
        return result[0] if result else None

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Check if string is a valid IPv4 or IPv6 address."""
        return validate_and_normalize_ip(ip_str) is not None

    @staticmethod
    def get_ip_version(ip_str: str) -> Optional[int]:
        """Get IP version (4 or 6) if valid, else None."""
        result = validate_and_normalize_ip(ip_str)
        return result[1] if result else None

    @staticmethod
    def extract_unique_ips_from_records(
        dns_records: Sequence[DNSRecord],
    ) -> List[Dict[str, Any]]:
        """
        Extract, validate, normalize, and deduplicate IP addresses originating from
        existing A and AAAA DNSRecord observations.
        
        Returns a list of dicts:
        [
            {
                "ip_address": "93.184.216.34",
                "ip_version": 4,
                "is_public": True,
                "subdomain_ids": [UUID, ...],
            },
            ...
        ]
        """
        seen: Dict[str, Dict[str, Any]] = {}

        for rec in dns_records:
            if rec.record_type not in ("A", "AAAA"):
                continue

            val = rec.value
            parsed = validate_and_normalize_ip(val)
            if not parsed:
                logger.warning(
                    f"DNSRecord '{rec.id}' has invalid IP value '{val}' for type '{rec.record_type}'. Skipping."
                )
                continue

            normalized_ip, ip_version, is_public = parsed

            if normalized_ip not in seen:
                seen[normalized_ip] = {
                    "ip_address": normalized_ip,
                    "ip_version": ip_version,
                    "is_public": is_public,
                    "subdomain_ids": [rec.subdomain_id],
                }
            else:
                if rec.subdomain_id not in seen[normalized_ip]["subdomain_ids"]:
                    seen[normalized_ip]["subdomain_ids"].append(rec.subdomain_id)

        return list(seen.values())
