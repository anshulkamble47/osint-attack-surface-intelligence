"""Domain validation, normalization, and subdomain boundary utilities."""

import re
from urllib.parse import urlparse
from typing import Optional

# RFC 1035 / RFC 1123 compliant domain label pattern
DOMAIN_LABEL_REGEX = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")
# Overall domain validation pattern: at least 2 labels, valid TLD
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_domain(raw_input: str) -> str:
    """
    Normalize a raw user input, URL, or hostname into a clean FQDN domain string.
    
    Examples:
        - "https://Example.COM:8080/path?arg=1" -> "example.com"
        - "http://sub.example.com/"            -> "sub.example.com"
        - "  EXAMPLE.COM.  "                   -> "example.com"
        - "*.api.example.com"                  -> "api.example.com"
    """
    if not raw_input or not isinstance(raw_input, str):
        return ""

    cleaned = raw_input.strip().lower()

    # If input looks like a URL with scheme, parse network location
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    elif "/" in cleaned:
        # e.g. "example.com/path"
        cleaned = cleaned.split("/")[0]

    # Strip port if present (e.g. "example.com:443")
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]

    # Strip wildcard prefixes (e.g. "*.example.com" or "*.")
    while cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if cleaned.startswith("*"):
        cleaned = cleaned[1:]

    # Strip leading/trailing dots and whitespace
    cleaned = cleaned.strip(". ")

    return cleaned


def is_valid_domain(domain: str) -> bool:
    """
    Validate that a given string is a syntactically valid public domain name.
    
    Checks:
    - Non-empty and total length <= 253 characters
    - Must contain at least one dot separating labels
    - Each label must be 1-63 characters and contain valid characters [a-z0-9-]
    - Labels must not start or end with hyphens
    - Top Level Domain (TLD) must be alphabetical and >= 2 characters
    - Disallows IP addresses (e.g. 192.168.1.1) and localhost
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    if len(domain) > 253 or len(domain) < 3:
        return False

    if domain == "localhost" or domain.endswith(".local"):
        return False

    # Disallow IP addresses passed as domains
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    # Validate each label
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not DOMAIN_LABEL_REGEX.match(label):
            return False

    # Validate TLD is not numeric
    tld = labels[-1]
    if not re.match(r"^[a-zA-Z]{2,63}$", tld):
        return False

    return bool(DOMAIN_REGEX.match(domain))


def is_subdomain_of(candidate_hostname: str, target_domain: str) -> bool:
    """
    Strict domain-boundary check ensuring candidate_hostname is either the target_domain
    itself or an exact subdomain of target_domain.
    
    Prevents substring poisoning (e.g. 'notexample.com' matching 'example.com').
    
    Examples:
        - is_subdomain_of("example.com", "example.com") -> True
        - is_subdomain_of("api.example.com", "example.com") -> True
        - is_subdomain_of("dev.api.example.com", "example.com") -> True
        - is_subdomain_of("notexample.com", "example.com") -> False
        - is_subdomain_of("example.com.attacker.com", "example.com") -> False
    """
    if not candidate_hostname or not target_domain:
        return False

    cand = candidate_hostname.strip().lower()
    target = target_domain.strip().lower()

    if cand == target:
        return True

    return cand.endswith("." + target)
