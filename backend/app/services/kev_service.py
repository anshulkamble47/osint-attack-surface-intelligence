"""CISA Known Exploited Vulnerabilities (KEV) Intelligence Provider and Service."""

import json
from dataclasses import dataclass
from typing import Optional, Dict, Any, Union
import httpx

from backend.app.core.logging import logger


@dataclass
class KEVEntry:
    """Standardized CISA Known Exploited Vulnerability record."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: Optional[str] = None
    short_description: str = ""
    required_action: str = ""
    due_date: Optional[str] = None
    known_ransomware_campaign_use: str = "Unknown"  # Known, Unknown
    notes: Optional[str] = None
    raw_json: Optional[str] = None


class CISAKEVService:
    """
    Client and service for querying the official CISA Known Exploited Vulnerabilities catalog.
    
    Security & Reliability Properties:
    - Queries exclusively official CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json.
    - No arbitrary URL fetching.
    - Bounded response payload (5 MB limit).
    - Strict 5.0s timeouts.
    - In-memory catalog index keyed by normalized uppercase CVE ID (e.g. 'CVE-2021-44228').
    - Mockable client transport and offline catalog loading for unit tests.
    """

    CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    DEFAULT_TIMEOUT_SECONDS = 5.0
    MAX_RESPONSE_BYTES = 5242880  # 5 MB

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        initial_catalog: Optional[Dict[str, Any]] = None,
    ):
        self._client = client
        self._timeout = timeout
        self._catalog: Dict[str, KEVEntry] = {}
        if initial_catalog:
            self.load_catalog(initial_catalog)

    def is_kev(self, cve_id: str) -> bool:
        """Check if a given CVE identifier is present in the CISA KEV catalog."""
        clean_cve = (cve_id or "").strip().upper()
        return clean_cve in self._catalog

    def get_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """Retrieve full CISA KEV metadata for a CVE if listed."""
        clean_cve = (cve_id or "").strip().upper()
        return self._catalog.get(clean_cve)

    def count(self) -> int:
        """Return total number of loaded CISA KEV entries."""
        return len(self._catalog)

    def load_catalog(self, catalog_data: Union[str, Dict[str, Any]]) -> int:
        """Load and index CISA KEV catalog entries into memory."""
        try:
            if isinstance(catalog_data, str):
                data = json.loads(catalog_data)
            else:
                data = catalog_data

            if not isinstance(data, dict):
                logger.warning("CISA KEV catalog payload is not a valid JSON dictionary")
                return 0

            vulns = data.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                logger.warning("CISA KEV catalog 'vulnerabilities' field is not a list")
                return 0

            count = 0
            for item in vulns:
                if not isinstance(item, dict):
                    continue
                cve_id = item.get("cveID") or item.get("cve_id")
                if not cve_id or not isinstance(cve_id, str):
                    continue

                clean_cve = cve_id.strip().upper()
                entry = KEVEntry(
                    cve_id=clean_cve,
                    vendor_project=item.get("vendorProject", "Unknown"),
                    product=item.get("product", "Unknown"),
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded"),
                    short_description=item.get("shortDescription", ""),
                    required_action=item.get("requiredAction", ""),
                    due_date=item.get("dueDate"),
                    known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                    notes=item.get("notes"),
                    raw_json=json.dumps(item),
                )
                self._catalog[clean_cve] = entry
                count += 1

            logger.info(f"Loaded {count} CISA KEV catalog entries into index.")
            return count

        except Exception as exc:
            logger.error(f"Failed to load CISA KEV catalog: {exc}")
            return 0

    def fetch_catalog(self) -> bool:
        """Fetch latest KEV catalog from official CISA feed."""
        try:
            headers = {
                "User-Agent": "OSINT-AttackSurfacePlatform/1.0 (Defensive Security Intelligence)",
                "Accept": "application/json",
            }

            if self._client:
                resp = self._client.get(
                    self.CISA_KEV_FEED_URL,
                    headers=headers,
                    timeout=self._timeout,
                )
                if resp.status_code != 200:
                    logger.warning(f"CISA KEV feed returned HTTP status {resp.status_code}")
                    return False
                raw_text = resp.text[: self.MAX_RESPONSE_BYTES]
                self.load_catalog(raw_text)
                return True

            else:
                with httpx.Client(timeout=self._timeout) as client:
                    resp = client.get(
                        self.CISA_KEV_FEED_URL,
                        headers=headers,
                    )
                    if resp.status_code != 200:
                        logger.warning(f"CISA KEV feed returned HTTP status {resp.status_code}")
                        return False
                    raw_text = resp.text[: self.MAX_RESPONSE_BYTES]
                    self.load_catalog(raw_text)
                    return True

        except httpx.TimeoutException:
            logger.warning("CISA KEV feed request timed out")
            return False
        except httpx.HTTPError as exc:
            logger.warning(f"CISA KEV feed network error: {exc}")
            return False
        except Exception as exc:
            logger.error(f"Unexpected error fetching CISA KEV feed: {exc}")
            return False
