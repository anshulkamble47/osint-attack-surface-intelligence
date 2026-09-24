"""NVD / CVE Intelligence Provider and Service."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
import httpx

from backend.app.core.logging import logger
from backend.app.core.config import settings


@dataclass
class VersionConstraint:
    """Structured version boundary criteria from NVD configurations."""
    cpe_prefix: str
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    exact_version: Optional[str] = None


@dataclass
class CVEMetadata:
    """Standardized CVE intelligence record extracted from NVD / external catalogs."""
    cve_id: str
    description: str
    severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_cpe_patterns: List[str] = field(default_factory=list)
    version_constraints: List[VersionConstraint] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    references: List[Dict[str, Any]] = field(default_factory=list)
    source: str = "NVD"
    raw_json: Optional[str] = None


class NVDService:
    """
    Client and service for querying official NIST NVD API 2.0 vulnerability data.
    
    Security & Reliability Properties:
    - Queries exclusively official NIST NVD endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0.
    - No arbitrary URL fetching.
    - Bounded response payload (1 MB limit).
    - Strict 5.0s timeouts.
    - Graceful error handling for rate limits (HTTP 429/503), timeouts, and malformed data.
    - Mockable client injection for automated tests.
    """

    NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_TIMEOUT_SECONDS = 5.0
    MAX_RESPONSE_BYTES = 1048576  # 1 MB

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._client = client
        self._api_key = api_key or getattr(settings, "NVD_API_KEY", None)
        self._timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "OSINT-AttackSurfacePlatform/1.0 (Defensive Security Intelligence)",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def fetch_cve(self, cve_id: str) -> Optional[CVEMetadata]:
        """Fetch details for a specific CVE identifier (e.g. CVE-2021-44228)."""
        clean_cve = cve_id.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,8}$", clean_cve):
            logger.warning(f"Invalid CVE identifier format: '{cve_id}'")
            return None

        params = {"cveId": clean_cve}
        return self._execute_query(params, single=True)

    def search_by_cpe(self, cpe_name: str, limit: int = 20) -> List[CVEMetadata]:
        """Search NVD CVEs matching a CPE 2.3 URI pattern."""
        clean_cpe = cpe_name.strip()
        params = {
            "cpeName": clean_cpe,
            "resultsPerPage": str(min(limit, 50)),
        }
        return self._execute_query_list(params)

    def search_by_keyword(self, keyword: str, limit: int = 20) -> List[CVEMetadata]:
        """Search NVD CVEs matching a keyword."""
        clean_kw = keyword.strip()
        if not clean_kw:
            return []
        params = {
            "keywordSearch": clean_kw,
            "resultsPerPage": str(min(limit, 50)),
        }
        return self._execute_query_list(params)

    def _execute_query(self, params: Dict[str, str], single: bool = True) -> Optional[CVEMetadata]:
        results = self._execute_query_list(params)
        return results[0] if results else None

    def _execute_query_list(self, params: Dict[str, str]) -> List[CVEMetadata]:
        """Execute HTTP request against NVD API and parse results."""
        try:
            if self._client:
                # Injected mock/test client
                resp = self._client.get(
                    self.NVD_API_BASE_URL,
                    params=params,
                    headers=self._get_headers(),
                    timeout=self._timeout,
                )
                if resp.status_code != 200:
                    logger.warning(f"NVD API returned status {resp.status_code} for params {params}")
                    return []
                raw_text = resp.text[: self.MAX_RESPONSE_BYTES]
                data = json.loads(raw_text)
                return self.parse_nvd_response(data, raw_json_str=raw_text)

            else:
                # Production HTTP client
                with httpx.Client(timeout=self._timeout) as client:
                    resp = client.get(
                        self.NVD_API_BASE_URL,
                        params=params,
                        headers=self._get_headers(),
                    )
                    if resp.status_code != 200:
                        logger.warning(f"NVD API returned status {resp.status_code} for params {params}")
                        return []
                    raw_text = resp.text[: self.MAX_RESPONSE_BYTES]
                    data = json.loads(raw_text)
                    return self.parse_nvd_response(data, raw_json_str=raw_text)

        except httpx.TimeoutException:
            logger.warning(f"NVD API request timed out for params {params}")
            return []
        except httpx.HTTPError as exc:
            logger.warning(f"NVD API network error: {exc}")
            return []
        except json.JSONDecodeError as exc:
            logger.warning(f"NVD API returned malformed JSON: {exc}")
            return []
        except Exception as exc:
            logger.error(f"Unexpected error querying NVD API: {exc}")
            return []

    @classmethod
    def parse_nvd_response(
        cls, data: Dict[str, Any], raw_json_str: Optional[str] = None
    ) -> List[CVEMetadata]:
        """Parse NVD 2.0 API JSON payload into structured CVEMetadata items."""
        items: List[CVEMetadata] = []
        if not isinstance(data, dict):
            return items

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return items

        for vuln_wrap in vulnerabilities:
            if not isinstance(vuln_wrap, dict):
                continue
            cve_dict = vuln_wrap.get("cve", {})
            if not isinstance(cve_dict, dict):
                continue

            cve_id = cve_dict.get("id")
            if not cve_id or not isinstance(cve_id, str):
                continue

            # 1. Description
            descriptions = cve_dict.get("descriptions", [])
            desc_text = "No description provided."
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en":
                    desc_text = d.get("value", desc_text)
                    break
                elif isinstance(d, dict) and "value" in d:
                    desc_text = d.get("value")

            # 2. CVSS Metrics & Severity
            metrics = cve_dict.get("metrics", {})
            cvss_v3 = None
            cvss_v2 = None
            severity = "UNKNOWN"
            vector_str = None

            # CVSS v3.1 or v3.0
            v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            if isinstance(v3_list, list) and len(v3_list) > 0 and isinstance(v3_list[0], dict):
                v3_data = v3_list[0].get("cvssData", {})
                cvss_v3 = v3_data.get("baseScore")
                vector_str = v3_data.get("vectorString")
                severity = (
                    v3_data.get("baseSeverity")
                    or v3_list[0].get("baseSeverity")
                    or "UNKNOWN"
                ).upper()

            # CVSS v2 fallback
            v2_list = metrics.get("cvssMetricV2") or []
            if isinstance(v2_list, list) and len(v2_list) > 0 and isinstance(v2_list[0], dict):
                v2_data = v2_list[0].get("cvssData", {})
                cvss_v2 = v2_data.get("baseScore")
                if severity == "UNKNOWN":
                    severity = (v2_list[0].get("baseSeverity") or "UNKNOWN").upper()

            # 3. Affected CPE patterns & Version constraints
            cpe_patterns: List[str] = []
            constraints: List[VersionConstraint] = []
            configurations = cve_dict.get("configurations", [])
            if isinstance(configurations, list):
                for config in configurations:
                    if not isinstance(config, dict):
                        continue
                    nodes = config.get("nodes", [])
                    if isinstance(nodes, list):
                        for node in nodes:
                            if not isinstance(node, dict):
                                continue
                            cpe_matches = node.get("cpeMatch", [])
                            if isinstance(cpe_matches, list):
                                for match in cpe_matches:
                                    if not isinstance(match, dict) or not match.get("vulnerable", False):
                                        continue
                                    criteria = match.get("criteria", "")
                                    if criteria:
                                        cpe_patterns.append(criteria)

                                        # Extract version constraint
                                        v_start_inc = match.get("versionStartIncluding")
                                        v_start_exc = match.get("versionStartExcluding")
                                        v_end_inc = match.get("versionEndIncluding")
                                        v_end_exc = match.get("versionEndExcluding")

                                        # If criteria has explicit version (e.g. cpe:2.3:a:nginx:nginx:1.20.1:...)
                                        exact_v = None
                                        parts = criteria.split(":")
                                        if len(parts) >= 6 and parts[5] not in ("*", "-"):
                                            exact_v = parts[5]

                                        constraints.append(
                                            VersionConstraint(
                                                cpe_prefix=":".join(parts[:5]) if len(parts) >= 5 else criteria,
                                                version_start_including=v_start_inc,
                                                version_start_excluding=v_start_exc,
                                                version_end_including=v_end_inc,
                                                version_end_excluding=v_end_exc,
                                                exact_version=exact_v,
                                            )
                                        )

            # 4. Dates
            pub_date = cls._parse_iso_date(cve_dict.get("published"))
            mod_date = cls._parse_iso_date(cve_dict.get("lastModified"))

            # 5. References
            ref_list: List[Dict[str, Any]] = []
            for ref in cve_dict.get("references", []):
                if isinstance(ref, dict) and ref.get("url"):
                    ref_list.append({
                        "url": ref.get("url"),
                        "source": ref.get("source", "NVD"),
                        "tags": ref.get("tags", []),
                    })

            items.append(
                CVEMetadata(
                    cve_id=cve_id,
                    description=desc_text,
                    severity=severity,
                    cvss_v3_score=cvss_v3,
                    cvss_v2_score=cvss_v2,
                    cvss_vector=vector_str,
                    affected_cpe_patterns=list(set(cpe_patterns)),
                    version_constraints=constraints,
                    published_date=pub_date,
                    last_modified_date=mod_date,
                    references=ref_list,
                    source="NVD",
                    raw_json=raw_json_str,
                )
            )

        return items

    @staticmethod
    def _parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str or not isinstance(date_str, str):
            return None
        try:
            # Handles '2021-12-10T10:15:00.000' or with timezone
            cleaned = date_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
