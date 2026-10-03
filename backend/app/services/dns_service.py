"""Active DNS Intelligence Service for resolving hostnames and resource records."""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set, Any, Dict
import dns.resolver
import dns.exception

from backend.app.core.config import settings
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


class DNSCache:
    """Thread-safe, per-ScanRun in-memory DNS resolution cache."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cache: Dict[str, DNSResolutionResult] = {}

    def get(self, hostname: str) -> Optional[DNSResolutionResult]:
        key = hostname.strip().rstrip(".").lower()
        with self._lock:
            cached = self._cache.get(key)
            if cached:
                return DNSResolutionResult(
                    hostname=cached.hostname,
                    is_resolving=cached.is_resolving,
                    records=list(cached.records),
                    error=cached.error,
                )
            return None

    def set(self, hostname: str, result: DNSResolutionResult) -> None:
        key = hostname.strip().rstrip(".").lower()
        with self._lock:
            self._cache[key] = result

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


class DNSService:
    """
    Active DNS resolution service querying standard and custom DNS resolvers.
    Resolves A, AAAA, CNAME, MX, NS, and TXT records with bounded concurrency,
    strict timeouts, fast-fail handling, and per-ScanRun memory caching.
    """

    DEFAULT_RECORD_TYPES = settings.DNS_RECORD_TYPES
    DEFAULT_TIMEOUT_SECONDS = settings.DNS_QUERY_TIMEOUT
    DEFAULT_LIFETIME_SECONDS = settings.DNS_LIFETIME_TIMEOUT

    def __init__(
        self,
        resolver: Optional[dns.resolver.Resolver] = None,
        timeout: Optional[float] = None,
        lifetime: Optional[float] = None,
        cache: Optional[DNSCache] = None,
    ):
        self._timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS
        self._lifetime = lifetime if lifetime is not None else self.DEFAULT_LIFETIME_SECONDS
        self._cache = cache if cache is not None else DNSCache()

        if resolver:
            self._resolver = resolver
            if not hasattr(resolver, "timeout") or resolver.timeout is None:
                self._resolver.timeout = self._timeout
            if not hasattr(resolver, "lifetime") or resolver.lifetime is None:
                self._resolver.lifetime = self._lifetime
        else:
            self._resolver = dns.resolver.Resolver()
            self._resolver.timeout = self._timeout
            self._resolver.lifetime = self._lifetime

    @property
    def cache(self) -> DNSCache:
        """Access the thread-safe resolution cache."""
        return self._cache

    def resolve(
        self,
        hostname: str,
        record_types: Optional[List[str]] = None,
        is_root_target: bool = False,
    ) -> DNSResolutionResult:
        """
        Query DNS resource records for the given hostname.
        
        Uses smart query ordering:
        - Evaluates primary address records (A, AAAA, CNAME) first.
        - Fails fast on NXDOMAIN and NoNameservers to prevent wasted queries.
        - Queries auxiliary records (MX, NS, TXT) if no fatal zone failure occurred.
        - Utilizes per-ScanRun in-memory caching to avoid redundant queries.
        """
        cleaned_hostname = hostname.strip().rstrip(".")
        if not cleaned_hostname:
            return DNSResolutionResult(
                hostname="",
                is_resolving=False,
                records=[],
                error="Empty Hostname",
            )

        # 1. Check in-memory resolution cache
        cached_result = self._cache.get(cleaned_hostname)
        if cached_result is not None:
            return cached_result

        types_to_query = record_types or self.DEFAULT_RECORD_TYPES
        discovered_records: List[DNSObservation] = []
        is_resolving = False
        last_error: Optional[str] = None
        seen_record_keys: Set[tuple] = set()
        failed_fast = False

        resolver_info = "system_resolver"
        if self._resolver.nameservers:
            resolver_info = str(self._resolver.nameservers[0])

        primary_types = [t for t in types_to_query if t in ("A", "AAAA", "CNAME")]
        auxiliary_types = [t for t in types_to_query if t not in ("A", "AAAA", "CNAME")]

        # Query primary types first
        for rtype in primary_types:
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
                        is_resolving = True

            except dns.resolver.NXDOMAIN:
                # Hostname does not exist in DNS hierarchy - Fail fast immediately
                last_error = "NXDOMAIN"
                failed_fast = True
                break
            except dns.resolver.NoNameservers:
                # No responsive nameservers for this zone - Fail fast immediately
                logger.debug(f"No nameservers available for '{cleaned_hostname}'")
                last_error = "No Nameservers Available"
                failed_fast = True
                break
            except dns.resolver.NoAnswer:
                # Specific record type does not exist for this name; continue
                continue
            except dns.resolver.Timeout:
                logger.debug(f"DNS timeout querying {rtype} for '{cleaned_hostname}'")
                last_error = "Query Timeout"
            except dns.exception.DNSException as exc:
                logger.debug(f"DNS error ({rtype}) for '{cleaned_hostname}': {exc}")
                last_error = str(exc)
            except Exception as exc:
                logger.error(f"Unexpected error resolving '{cleaned_hostname}': {exc}")
                last_error = str(exc)

        # Query auxiliary types (MX, NS, TXT) if no fatal zone failure occurred
        if not failed_fast and auxiliary_types:
            for rtype in auxiliary_types:
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
                            is_resolving = True
                except dns.resolver.NXDOMAIN:
                    last_error = "NXDOMAIN"
                    break
                except dns.resolver.NoNameservers:
                    last_error = "No Nameservers Available"
                    break
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.Timeout:
                    last_error = "Query Timeout"
                except dns.exception.DNSException as exc:
                    last_error = str(exc)
                except Exception as exc:
                    logger.debug(f"Auxiliary DNS lookup error ({rtype}) for '{cleaned_hostname}': {exc}")

        if discovered_records and not is_resolving:
            is_resolving = True

        result = DNSResolutionResult(
            hostname=cleaned_hostname,
            is_resolving=is_resolving,
            records=discovered_records,
            error=last_error if not is_resolving else None,
        )

        # Cache the result
        self._cache.set(cleaned_hostname, result)
        return result

    def resolve_batch(
        self,
        hostnames: List[str],
        max_concurrency: Optional[int] = None,
        record_types: Optional[List[str]] = None,
        root_domain: Optional[str] = None,
    ) -> Dict[str, DNSResolutionResult]:
        """
        Concurrently resolve a collection of hostnames with bounded concurrency.
        
        Preserves error isolation per host and returns a map of hostname -> DNSResolutionResult.
        """
        if not hostnames:
            return {}

        concurrency = max_concurrency or settings.DNS_MAX_CONCURRENCY
        concurrency = max(1, min(concurrency, len(hostnames)))

        results: Dict[str, DNSResolutionResult] = {}
        cleaned_root = root_domain.strip().rstrip(".").lower() if root_domain else None

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="dns-worker") as executor:
            future_to_host = {
                executor.submit(
                    self.resolve,
                    host,
                    record_types,
                    bool(cleaned_root and host.strip().rstrip(".").lower() == cleaned_root),
                ): host
                for host in hostnames
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    res = future.result()
                    results[host] = res
                except Exception as exc:
                    logger.error(f"Worker exception resolving '{host}': {exc}")
                    results[host] = DNSResolutionResult(
                        hostname=host,
                        is_resolving=False,
                        records=[],
                        error=str(exc),
                    )

        return results

    @staticmethod
    def _format_rdata(rtype: str, rdata: Any) -> str:
        """Format DNS rdata into standardized text representation."""
        if rtype == "MX":
            return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
        elif rtype in ("CNAME", "NS", "PTR"):
            return str(rdata.target).rstrip(".")
        elif rtype == "TXT":
            if hasattr(rdata, "strings"):
                return "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            return str(rdata).strip('"')
        return str(rdata).strip()
