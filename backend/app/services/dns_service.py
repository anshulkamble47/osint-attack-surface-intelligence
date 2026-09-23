"""Active DNS Intelligence Service for resolving hostnames and resource records."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set, Any
import dns.resolver
import dns.exception

from backend.app.core.logging import logger


@dataclass
class DNSObservation:
    """Individual DNS resource record observation."""
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT
    value: str
    ttl: Optional[int] = None
    resolver: str = "system_resolver"
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DNSResolutionResult:
    """Consolidated DNS resolution result for a single hostname."""
    hostname: str
    is_resolving: bool
    records: List[DNSObservation] = field(default_factory=list)
    error: Optional[str] = None


class DNSService:
    """
    Active DNS resolution service querying standard and custom DNS resolvers.
    Resolves A, AAAA, CNAME, MX, NS, and TXT records with graceful error handling.
    """

    DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
    DEFAULT_TIMEOUT_SECONDS = 2.0
    DEFAULT_LIFETIME_SECONDS = 3.0

    def __init__(
        self,
        resolver: Optional[dns.resolver.Resolver] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        lifetime: float = DEFAULT_LIFETIME_SECONDS,
    ):
        if resolver:
            self._resolver = resolver
        else:
            self._resolver = dns.resolver.Resolver()
            self._resolver.timeout = timeout
            self._resolver.lifetime = lifetime

    def resolve(
        self,
        hostname: str,
        record_types: Optional[List[str]] = None,
    ) -> DNSResolutionResult:
        """
        Query DNS resource records for the given hostname.
        
        Handles NXDOMAIN, NoAnswer, Timeout, and DNSException without halting execution.
        Returns a DNSResolutionResult indicating whether the hostname actively resolves.
        """
        cleaned_hostname = hostname.strip().rstrip(".")
        types_to_query = record_types or self.DEFAULT_RECORD_TYPES
        discovered_records: List[DNSObservation] = []
        is_resolving = False
        last_error: Optional[str] = None
        seen_record_keys: Set[tuple] = set()

        resolver_info = "system_resolver"
        if self._resolver.nameservers:
            resolver_info = str(self._resolver.nameservers[0])

        for rtype in types_to_query:
            try:
                answers = self._resolver.resolve(cleaned_hostname, rtype)
                ttl = answers.rrset.ttl if answers.rrset else None

                for rdata in answers:
                    val_str = self._format_rdata(rtype, rdata)
                    record_key = (rtype, val_str)
                    if record_key not in seen_record_keys:
                        seen_record_keys.add(record_key)
                        discovered_records.append(
                            DNSObservation(
                                record_type=rtype,
                                value=val_str,
                                ttl=ttl,
                                resolver=resolver_info,
                            )
                        )
                        # An active A, AAAA, or CNAME proves reachability/resolution
                        if rtype in ("A", "AAAA", "CNAME"):
                            is_resolving = True

            except dns.resolver.NXDOMAIN:
                # Hostname does not exist
                last_error = "NXDOMAIN"
                break  # If NXDOMAIN, other record types will also not exist
            except dns.resolver.NoAnswer:
                # Specific record type does not exist for this name
                continue
            except dns.resolver.Timeout:
                logger.warning(f"DNS timeout querying {rtype} for '{cleaned_hostname}'")
                last_error = "Query Timeout"
            except dns.resolver.NoNameservers:
                logger.warning(f"No nameservers available for '{cleaned_hostname}'")
                last_error = "No Nameservers Available"
            except dns.exception.DNSException as exc:
                logger.warning(f"DNS error ({rtype}) for '{cleaned_hostname}': {exc}")
                last_error = str(exc)
            except Exception as exc:
                logger.error(f"Unexpected error resolving '{cleaned_hostname}': {exc}")
                last_error = str(exc)

        # If any valid record was discovered (even MX or NS), mark as resolving
        if discovered_records and not is_resolving:
            is_resolving = True

        return DNSResolutionResult(
            hostname=cleaned_hostname,
            is_resolving=is_resolving,
            records=discovered_records,
            error=last_error if not is_resolving else None,
        )

    @staticmethod
    def _format_rdata(rtype: str, rdata: Any) -> str:
        """Format DNS rdata into standardized text representation."""
        if rtype == "MX":
            return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
        elif rtype in ("CNAME", "NS", "PTR"):
            return str(rdata.target).rstrip(".")
        elif rtype == "TXT":
            # Join multiple TXT strings if chunked
            if hasattr(rdata, "strings"):
                return "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            return str(rdata).strip('"')
        return str(rdata).strip()
