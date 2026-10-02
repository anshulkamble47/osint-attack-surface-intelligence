"""Certificate Transparency (CT) discovery service with multi-provider fallback architecture."""

from abc import ABC, abstractmethod
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.utils.domain import normalize_domain, is_valid_domain, is_subdomain_of


class CTProviderError(Exception):
    """Exception raised when an external Certificate Transparency provider fails."""
    pass


@dataclass
class CTRecord:
    """Normalized Certificate Transparency observation."""
    fingerprint_sha256: str
    subject_cn: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    san_list: List[str]
    is_expired: bool
    ct_log_id: Optional[str] = None
    serial_number: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class CTDiscoveryResult:
    """Consolidated result of a Certificate Transparency discovery execution."""
    target_domain: str
    source: str
    provider_used: str
    fallback_used: bool
    provider_attempts: Dict[str, str]
    hostnames: List[str]
    certificates: List[CTRecord]
    retrieval_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseCTProvider(ABC):
    """Abstract base class for Certificate Transparency log providers."""
    name: str

    @abstractmethod
    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query external Certificate Transparency provider for certificates matching domain.
        Returns a list of raw certificate records.
        """
        pass


class CrtShProvider(BaseCTProvider):
    """Primary Certificate Transparency log provider querying crt.sh JSON endpoint."""

    name: str = "crt.sh"
    BASE_URL = "https://crt.sh"
    DEFAULT_TIMEOUT_SECONDS = 15.0
    MAX_RETRIES = 2
    RETRYABLE_STATUS_CODES = {429, 502, 503, 504, 520, 521, 522, 524}
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = MAX_RETRIES,
    ):
        self._client = client
        self._timeout = timeout
        self._max_retries = max_retries

    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query crt.sh JSON endpoint for certificates matching %.domain and domain.
        Uses exponential backoff with jitter and query fallback on transient upstream failures.
        Returns the raw list of JSON certificate dictionaries.
        """
        import time
        import random

        query_candidates = [f"%.{domain}", domain]
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        }

        last_error: Optional[Exception] = None

        for q_param in query_candidates:
            params = {"q": q_param, "output": "json"}

            for attempt in range(self._max_retries):
                if attempt > 0:
                    # Exponential backoff with jitter
                    backoff_delay = min(1.5 * (1.5 ** attempt) + random.uniform(0.2, 0.6), 5.0)
                    if self._client is None or self._timeout > 2.0:
                        time.sleep(backoff_delay)

                try:
                    if self._client:
                        response = self._client.get(
                            self.BASE_URL,
                            params=params,
                            headers=headers,
                            timeout=self._timeout,
                        )
                    else:
                        with httpx.Client(timeout=self._timeout) as client:
                            response = client.get(
                                self.BASE_URL,
                                params=params,
                                headers=headers,
                            )

                    # Successful response handling
                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")
                        raw_text = response.text.strip()
                        if "application/json" not in content_type and not raw_text.startswith("["):
                            logger.warning(
                                f"crt.sh returned non-JSON 200 for '{domain}' (query: '{q_param}'): {raw_text[:200]}"
                            )
                            if attempt < self._max_retries - 1:
                                continue
                            last_error = CTProviderError("Certificate Transparency provider returned non-JSON content")
                            continue

                        try:
                            data = response.json()
                            if isinstance(data, list):
                                return data
                            return []
                        except Exception as json_err:
                            logger.warning(f"Error parsing crt.sh JSON response for '{domain}': {json_err}")
                            if attempt < self._max_retries - 1:
                                continue
                            last_error = CTProviderError(f"Invalid JSON in Certificate Transparency response: {json_err}")
                            continue

                    # 404 from crt.sh means no certificates found for query
                    if response.status_code == 404:
                        logger.info(f"crt.sh returned 404 (0 certificates found) for query '{q_param}'")
                        return []

                    # Retryable transient upstream errors (502, 503, 504, 429)
                    if response.status_code in self.RETRYABLE_STATUS_CODES:
                        logger.warning(
                            f"crt.sh returned transient status {response.status_code} for '{domain}' "
                            f"(query: '{q_param}', attempt {attempt + 1}/{self._max_retries})"
                        )
                        last_error = CTProviderError(
                            f"Certificate Transparency provider unavailable (HTTP {response.status_code})"
                        )
                        if attempt < self._max_retries - 1:
                            continue
                        break

                    # Non-retryable HTTP errors (e.g. 400, 403)
                    logger.error(f"crt.sh returned non-retryable HTTP status {response.status_code} for '{domain}'")
                    raise CTProviderError(f"Certificate Transparency provider error (HTTP {response.status_code})")

                except httpx.TimeoutException as exc:
                    logger.warning(
                        f"Timeout querying crt.sh for '{domain}' "
                        f"(query: '{q_param}', attempt {attempt + 1}/{self._max_retries}): {exc}"
                    )
                    last_error = CTProviderError(
                        "Timeout connecting to Certificate Transparency log provider (crt.sh)"
                    )
                    if attempt < self._max_retries - 1:
                        continue
                    break

                except httpx.RequestError as exc:
                    logger.warning(
                        f"Network error querying crt.sh for '{domain}' "
                        f"(query: '{q_param}', attempt {attempt + 1}/{self._max_retries}): {exc}"
                    )
                    last_error = CTProviderError(
                        "Network communication failure querying Certificate Transparency logs"
                    )
                    if attempt < self._max_retries - 1:
                        continue
                    break

                except Exception as exc:
                    if isinstance(exc, CTProviderError):
                        raise
                    logger.error(f"Unexpected error querying crt.sh for '{domain}': {exc}")
                    last_error = CTProviderError(
                        f"Failed to process Certificate Transparency response: {str(exc)}"
                    )
                    if attempt < self._max_retries - 1:
                        continue
                    break

        if last_error:
            raise last_error
        return []


class CtLogsProvider(BaseCTProvider):
    """Secondary/fallback Certificate Transparency log provider querying ctlogs.dev REST API."""

    name: str = "ctlogs.dev"
    BASE_URL = "https://api.ctlogs.dev/v1/subdomains"
    DEFAULT_TIMEOUT_SECONDS = 15.0
    MAX_RETRIES = 2
    MAX_PAGES = 5  # Bounded pagination (up to 500 records) to maintain low latency
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504, 520, 521, 522, 524}
    USER_AGENT = "OSINT-Attack-Surface-Analyzer/0.1.0 (CT-Discovery-Client)"

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = MAX_RETRIES,
        max_pages: int = MAX_PAGES,
        api_key: Optional[str] = None,
    ):
        self._client = client
        self._timeout = timeout
        self._max_retries = max_retries
        self._max_pages = max_pages
        self._api_key = api_key or settings.CTLOGS_API_KEY

    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query ctlogs.dev /v1/subdomains/{domain} endpoint with pagination support.
        Maps records into the standard CT record format.
        """
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        all_records: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        for page in range(self._max_pages):
            url = f"{self.BASE_URL}/{domain}"
            params = {}
            if cursor:
                params["cursor"] = cursor

            last_page_error: Optional[Exception] = None

            for attempt in range(self._max_retries):
                try:
                    if self._client:
                        response = self._client.get(
                            url,
                            params=params,
                            headers=headers,
                            timeout=self._timeout,
                        )
                    else:
                        with httpx.Client(timeout=self._timeout) as client:
                            response = client.get(
                                url,
                                params=params,
                                headers=headers,
                            )

                    if response.status_code == 200:
                        try:
                            data = response.json()
                        except Exception as json_err:
                            logger.warning(f"Invalid JSON from ctlogs.dev for '{domain}': {json_err}")
                            last_page_error = CTProviderError(f"Invalid JSON from ctlogs.dev: {json_err}")
                            if attempt < self._max_retries - 1:
                                continue
                            break

                        rows = data.get("rows", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                        for row in rows:
                            if isinstance(row, dict):
                                match_name = row.get("match") or row.get("common_name") or row.get("name_value") or ""
                                all_records.append({
                                    "id": row.get("id"),
                                    "common_name": match_name,
                                    "name_value": match_name,
                                    "issuer_name": row.get("issuer") or row.get("issuer_name") or "Unknown Issuer",
                                    "not_before": row.get("not_before"),
                                    "not_after": row.get("not_after"),
                                    "serial_number": row.get("serial_hex") or row.get("serial_number"),
                                    "entry_timestamp": row.get("not_before"),
                                    "raw_ctlogs": row,
                                })

                        cursor = data.get("next_cursor") if isinstance(data, dict) else None
                        has_next = data.get("has_next", False) if isinstance(data, dict) else False

                        if not has_next or not cursor:
                            return all_records
                        break  # Page succeeded, proceed to next page

                    if response.status_code == 404:
                        logger.info(f"ctlogs.dev returned 404 (0 certificates) for '{domain}'")
                        return all_records

                    if response.status_code in self.RETRYABLE_STATUS_CODES:
                        logger.warning(
                            f"ctlogs.dev returned transient HTTP {response.status_code} for '{domain}' "
                            f"(attempt {attempt + 1}/{self._max_retries})"
                        )
                        last_page_error = CTProviderError(
                            f"Certificate Transparency fallback provider unavailable (HTTP {response.status_code})"
                        )
                        if attempt < self._max_retries - 1:
                            continue
                        break

                    logger.error(f"ctlogs.dev returned non-retryable HTTP {response.status_code} for '{domain}'")
                    raise CTProviderError(f"ctlogs.dev provider error (HTTP {response.status_code})")

                except httpx.TimeoutException as exc:
                    logger.warning(f"Timeout connecting to ctlogs.dev for '{domain}': {exc}")
                    last_page_error = CTProviderError("Timeout connecting to Certificate Transparency fallback provider (ctlogs.dev)")
                    if attempt < self._max_retries - 1:
                        continue
                    break

                except httpx.RequestError as exc:
                    logger.warning(f"Network error querying ctlogs.dev for '{domain}': {exc}")
                    last_page_error = CTProviderError("Network failure querying Certificate Transparency fallback provider (ctlogs.dev)")
                    if attempt < self._max_retries - 1:
                        continue
                    break

                except Exception as exc:
                    if isinstance(exc, CTProviderError):
                        raise
                    logger.error(f"Unexpected error querying ctlogs.dev for '{domain}': {exc}")
                    last_page_error = CTProviderError(f"Failed to process ctlogs.dev response: {str(exc)}")
                    if attempt < self._max_retries - 1:
                        continue
                    break

            if last_page_error and not all_records:
                raise last_page_error

        return all_records


class CTService:
    """
    High-level Certificate Transparency discovery service supporting multi-provider fallback.
    Attempts primary provider (crt.sh) first, and automatically fails over to fallback provider (ctlogs.dev)
    if the primary provider encounters upstream outages or timeouts.
    """

    def __init__(
        self,
        primary_provider: Optional[BaseCTProvider] = None,
        fallback_provider: Optional[BaseCTProvider] = None,
        fallback_enabled: bool = True,
        provider: Optional[BaseCTProvider] = None,
    ):
        self.primary_provider = primary_provider or provider or CrtShProvider()
        self.fallback_provider = fallback_provider or CtLogsProvider()
        self.fallback_enabled = fallback_enabled if fallback_enabled is not None else settings.CT_FALLBACK_ENABLED
        self.provider = self.primary_provider  # Backward-compatible attribute reference

    def discover(self, target_domain: str) -> CTDiscoveryResult:
        """
        Execute passive Certificate Transparency discovery for target_domain with multi-provider fallback.
        
        Workflow:
        1. Validate and normalize target domain boundary.
        2. Attempt discovery via primary provider (crt.sh).
        3. If primary provider fails with transient provider outage (502, 429, timeout, network error),
           attempt discovery via fallback provider (ctlogs.dev).
        4. Normalize hostnames, enforce domain boundaries, compute SHA-256 fingerprints, and deduplicate.
        5. Return consolidated CTDiscoveryResult with provenance tracking.
        """
        normalized_target = normalize_domain(target_domain)
        if not normalized_target or not is_valid_domain(normalized_target):
            raise ValueError(f"Invalid target domain for CT discovery: '{target_domain}'")

        now_utc = datetime.now(timezone.utc)
        provider_attempts: Dict[str, str] = {}
        primary_name = getattr(self.primary_provider, "name", "crt.sh")
        if not isinstance(primary_name, str):
            primary_name = "crt.sh"

        fallback_name = getattr(self.fallback_provider, "name", "ctlogs.dev")
        if not isinstance(fallback_name, str):
            fallback_name = "ctlogs.dev"

        provider_used = primary_name
        fallback_used = False
        raw_records: List[Dict[str, Any]] = []

        # Step 1: Attempt Primary Provider (crt.sh)
        try:
            raw_records = self.primary_provider.fetch_certificates(normalized_target)
            provider_used = primary_name
            provider_attempts[primary_name] = "success"
        except CTProviderError as primary_err:
            provider_attempts[primary_name] = str(primary_err)

            if self.fallback_enabled and self.fallback_provider:
                logger.warning(
                    f"Primary CT provider ({primary_name}) unavailable for '{normalized_target}': {primary_err}. "
                    f"Attempting fallback CT provider ({fallback_name})..."
                )
                try:
                    raw_records = self.fallback_provider.fetch_certificates(normalized_target)
                    provider_used = fallback_name
                    fallback_used = True
                    provider_attempts[fallback_name] = "success"
                    logger.info(
                        f"Fallback CT provider ({fallback_name}) succeeded for '{normalized_target}': "
                        f"{len(raw_records)} records retrieved."
                    )
                except CTProviderError as fallback_err:
                    provider_attempts[fallback_name] = str(fallback_err)
                    logger.error(
                        f"All CT providers failed for '{normalized_target}'. "
                        f"Primary ({primary_name}): {primary_err}; "
                        f"Fallback ({fallback_name}): {fallback_err}"
                    )
                    raise CTProviderError(
                        f"Certificate Transparency providers unavailable. "
                        f"Primary ({primary_name}): {primary_err}; "
                        f"Fallback ({fallback_name}): {fallback_err}"
                    )
            else:
                raise

        # Step 2: Unified Parsing, Boundary Validation, and Deduplication
        discovered_hostnames: Set[str] = set()
        certificates_by_fp: Dict[str, CTRecord] = {}

        # Always include the normalized target domain itself as a discovered asset
        discovered_hostnames.add(normalized_target)

        for record in raw_records:
            # Extract common name and SAN list
            common_name = record.get("common_name") or ""
            name_value = record.get("name_value") or ""
            issuer_name = record.get("issuer_name") or "Unknown Issuer"
            serial_number = str(record.get("serial_number")) if record.get("serial_number") is not None else None
            ct_id = record.get("id")

            # Parse validity timestamps
            valid_from = self._parse_datetime(record.get("not_before"))
            valid_to = self._parse_datetime(record.get("not_after"))
            if not valid_from:
                valid_from = now_utc
            if not valid_to:
                valid_to = now_utc

            is_expired = valid_to < now_utc

            # Parse all SAN names from name_value (split on newlines or commas)
            raw_sans = re.split(r"[\n,]+", name_value)
            san_candidates: List[str] = []
            for raw_san in raw_sans:
                norm_san = normalize_domain(raw_san)
                if norm_san and is_valid_domain(norm_san):
                    san_candidates.append(norm_san)
                    # Enforce strict domain boundary check
                    if is_subdomain_of(norm_san, normalized_target):
                        discovered_hostnames.add(norm_san)

            # Also check common_name
            norm_cn = normalize_domain(common_name)
            if norm_cn and is_valid_domain(norm_cn) and is_subdomain_of(norm_cn, normalized_target):
                discovered_hostnames.add(norm_cn)

            # Compute deterministic synthetic SHA-256 certificate identifier for deduplication
            if serial_number:
                fingerprint_seed = f"{issuer_name}|{serial_number}"
            else:
                fingerprint_seed = f"{issuer_name}|{common_name}|{valid_from.isoformat()}|{valid_to.isoformat()}"
            fingerprint_sha256 = hashlib.sha256(fingerprint_seed.encode("utf-8")).hexdigest()

            if fingerprint_sha256 in certificates_by_fp:
                # Merge SAN list for existing certificate
                existing_record = certificates_by_fp[fingerprint_sha256]
                merged_sans = sorted(list(set(existing_record.san_list + san_candidates)))
                existing_record.san_list = merged_sans
            else:
                ct_record = CTRecord(
                    fingerprint_sha256=fingerprint_sha256,
                    subject_cn=norm_cn or normalized_target,
                    issuer=issuer_name,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    san_list=sorted(list(set(san_candidates))),
                    is_expired=is_expired,
                    ct_log_id=str(ct_id) if ct_id is not None else None,
                    serial_number=serial_number,
                    raw_data={
                        "id": ct_id,
                        "issuer_name": issuer_name,
                        "entry_timestamp": record.get("entry_timestamp"),
                        "provider": provider_used,
                    },
                )
                certificates_by_fp[fingerprint_sha256] = ct_record

        # Sort hostnames alphabetically for deterministic output
        sorted_hostnames = sorted(list(discovered_hostnames))
        sorted_certs = sorted(
            list(certificates_by_fp.values()),
            key=lambda c: c.valid_to,
            reverse=True,
        )

        logger.info(
            f"CT discovery completed for '{normalized_target}' via {provider_used} (fallback={fallback_used}): "
            f"{len(sorted_hostnames)} hostnames, {len(sorted_certs)} certificates"
        )

        return CTDiscoveryResult(
            target_domain=normalized_target,
            source=provider_used,
            provider_used=provider_used,
            fallback_used=fallback_used,
            provider_attempts=provider_attempts,
            hostnames=sorted_hostnames,
            certificates=sorted_certs,
            retrieval_timestamp=now_utc,
        )

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """Safely parse various ISO/crt.sh/ctlogs datetime string formats into timezone-aware UTC datetime."""
        if not dt_str or not isinstance(dt_str, str):
            return None

        dt_str = dt_str.strip()
        # Supported format variants
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(dt_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        return None
