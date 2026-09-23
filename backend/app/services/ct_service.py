"""Certificate Transparency (CT) discovery service and crt.sh log provider."""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
import httpx

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
    hostnames: List[str]
    certificates: List[CTRecord]
    retrieval_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CrtShProvider:
    """Passive Certificate Transparency log aggregator client querying crt.sh."""

    BASE_URL = "https://crt.sh"
    DEFAULT_TIMEOUT_SECONDS = 12.0
    USER_AGENT = "AttackSurfacePlatform-OSINT/1.0 (+https://github.com/osint-platform)"

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._client = client
        self._timeout = timeout

    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query crt.sh JSON endpoint for all certificates matching %.domain and domain.
        Returns the raw list of JSON certificate dictionaries.
        """
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json",
        }

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

            if response.status_code != 200:
                logger.warning(
                    f"crt.sh returned non-200 status {response.status_code} for domain '{domain}'"
                )
                if response.status_code in (429, 502, 503, 504):
                    raise CTProviderError(
                        f"Certificate Transparency provider unavailable (HTTP {response.status_code})"
                    )
                return []

            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type and not response.text.strip().startswith("["):
                logger.warning(
                    f"crt.sh returned non-JSON content for domain '{domain}': {response.text[:200]}"
                )
                return []

            data = response.json()
            if isinstance(data, list):
                return data
            return []

        except httpx.TimeoutException as exc:
            logger.warning(f"Timeout querying crt.sh for '{domain}': {exc}")
            raise CTProviderError(
                f"Timeout connecting to Certificate Transparency log provider (crt.sh)"
            ) from exc
        except httpx.RequestError as exc:
            logger.warning(f"Network error querying crt.sh for '{domain}': {exc}")
            raise CTProviderError(
                f"Network communication failure querying Certificate Transparency logs"
            ) from exc
        except Exception as exc:
            if isinstance(exc, CTProviderError):
                raise
            logger.error(f"Unexpected error parsing crt.sh response for '{domain}': {exc}")
            raise CTProviderError(
                f"Failed to process Certificate Transparency response: {str(exc)}"
            ) from exc


class CTService:
    """
    High-level Certificate Transparency discovery service.
    Coordinates log fetching, domain boundary validation, hostname cleaning,
    and deduplication.
    """

    def __init__(self, provider: Optional[CrtShProvider] = None):
        self.provider = provider or CrtShProvider()

    def discover(self, target_domain: str) -> CTDiscoveryResult:
        """
        Execute passive Certificate Transparency discovery for target_domain.
        
        Steps:
        1. Validate and normalize target domain.
        2. Query CT logs.
        3. Parse certificate entries and extract SAN hostnames.
        4. Normalize hostnames and filter strictly by domain boundary.
        5. Deduplicate hostnames and certificates.
        6. Return consolidated CTDiscoveryResult.
        """
        normalized_target = normalize_domain(target_domain)
        if not normalized_target or not is_valid_domain(normalized_target):
            raise ValueError(f"Invalid target domain for CT discovery: '{target_domain}'")

        raw_records = self.provider.fetch_certificates(normalized_target)
        discovered_hostnames: Set[str] = set()
        certificates_by_fp: Dict[str, CTRecord] = {}

        now_utc = datetime.now(timezone.utc)

        # Always include the normalized target domain itself as a discovered asset
        discovered_hostnames.add(normalized_target)

        for record in raw_records:
            # Extract common name and SAN list
            common_name = record.get("common_name") or ""
            name_value = record.get("name_value") or ""
            issuer_name = record.get("issuer_name") or "Unknown Issuer"
            serial_number = record.get("serial_number")
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

            # Compute deterministic synthetic SHA-256 certificate identifier for deduplication.
            # NOTE: The crt.sh JSON API returns certificate metadata rather than raw X.509 DER bytes.
            # Thus, this hash is a deterministic identifier generated from (issuer + serial_number)
            # rather than the cryptographic digest of raw DER bytes. True DER hashing can be
            # populated when active TLS probing is conducted in future stages.
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
            f"CT discovery completed for '{normalized_target}': "
            f"{len(sorted_hostnames)} hostnames, {len(sorted_certs)} certificates"
        )

        return CTDiscoveryResult(
            target_domain=normalized_target,
            source="crt.sh",
            hostnames=sorted_hostnames,
            certificates=sorted_certs,
            retrieval_timestamp=now_utc,
        )

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """Safely parse various ISO/crt.sh datetime string formats into timezone-aware UTC datetime."""
        if not dt_str or not isinstance(dt_str, str):
            return None

        dt_str = dt_str.strip()
        # Supported format variants
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
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
